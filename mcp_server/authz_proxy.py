"""
MCP AuthZ Proxy
───────────────
This is the enforcement bridge that sits between AI agents and the
kubernetes-mcp-server. It intercepts every tool call, creates an
MCPToolInvocation CR in Kubernetes, waits for Kyverno to admit or
deny it via the admission webhook, then either forwards the call to
the real MCP server or returns a policy violation error.

Flow:
  Agent → AuthZ Proxy → MCPToolInvocation CR → Kyverno Webhook
                                                   ↓ (admit/deny)
                               MCP Server ← proxy forwards (if admitted)

This runs as a sidecar or standalone service in the same namespace
as the kubernetes-mcp-server.

Usage:
  pip install httpx kubernetes fastapi uvicorn
  python authz_proxy.py
  # Exposes :8090/mcp — point your agent here instead of :8080
"""

import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse
import uvicorn

# Try to load kubernetes client — optional if running outside cluster
try:
    from kubernetes import client, config as k8s_config
    try:
        k8s_config.load_incluster_config()
        K8S_AVAILABLE = True
    except Exception:
        try:
            k8s_config.load_kube_config()
            K8S_AVAILABLE = True
        except Exception:
            K8S_AVAILABLE = False
except ImportError:
    K8S_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("authz-proxy")

# ── Config ────────────────────────────────────────────────────────────────────

MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8080")
PROXY_PORT     = int(os.environ.get("PROXY_PORT", "8090"))
TENANT_ID      = os.environ.get("TENANT_ID", "tenant-acme")
AGENT_ID       = os.environ.get("AGENT_ID", "sre-agent")
MCP_GROUP      = "mcp.security.io"
MCP_VERSION    = "v1alpha1"
MCP_PLURAL     = "mcptoolinvocations"

app = FastAPI(title="MCP AuthZ Proxy", version="1.0.0")

# ── Kubernetes CR helpers ─────────────────────────────────────────────────────

def create_invocation_cr(tool_name: str, params: dict, triggered_by: str, reason: str) -> dict:
    """Create an MCPToolInvocation CR and let Kyverno evaluate it."""
    if not K8S_AVAILABLE:
        log.warning("K8s client not available — simulating CR creation")
        return {"simulated": True, "admitted": True}

    custom_api = client.CustomObjectsApi()
    name = f"proxy-{tool_name.replace('_', '-')}-{uuid.uuid4().hex[:6]}"

    body = {
        "apiVersion": f"{MCP_GROUP}/{MCP_VERSION}",
        "kind": "MCPToolInvocation",
        "metadata": {
            "name": name,
            "namespace": TENANT_ID,
            "labels": {
                "mcp.security.io/agent-id":  AGENT_ID,
                "mcp.security.io/tool-name": tool_name,
            },
        },
        "spec": {
            "toolName":    tool_name,
            "agentId":     AGENT_ID,
            "tenantId":    TENANT_ID,
            "triggeredBy": triggered_by,
            "reason":      reason,
            "parameters":  params,
        },
    }

    try:
        result = custom_api.create_namespaced_custom_object(
            group=MCP_GROUP,
            version=MCP_VERSION,
            namespace=TENANT_ID,
            plural=MCP_PLURAL,
            body=body,
        )
        log.info(f"CR admitted: {name}  tool={tool_name}")
        return {"admitted": True, "name": name, "cr": result}

    except client.ApiException as e:
        # 400 — Kyverno ValidatingPolicy (policies.kyverno.io/v1) denial
        # 403 — Kyverno ClusterPolicy (kyverno.io/v1) denial
        # 422 — Unprocessable entity (validation failure)
        if e.status in (400, 403, 422):
            body_json = json.loads(e.body) if e.body else {}
            message = (
                body_json.get("message", "")
                or body_json.get("details", {})
                              .get("causes", [{}])[0]
                              .get("message", "Policy violation")
            )
            log.warning(f"CR DENIED: {name}  tool={tool_name}  reason={message}")
            return {"admitted": False, "reason": message, "name": name}
        raise

# ── JSON-RPC helpers ──────────────────────────────────────────────────────────

def jsonrpc_error(id_, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}

def jsonrpc_result(id_, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}

# ── Proxy routes ──────────────────────────────────────────────────────────────

@app.post("/mcp")
async def proxy_mcp_post(request: Request):
    """
    Intercepts MCP tools/call requests.
    Non-invocation calls (initialize, tools/list etc.) pass through directly.
    For tools/call — creates MCPToolInvocation CR, Kyverno decides admit/deny.
    """
    body   = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")

    # Pass-through: non-tool-call methods go straight to MCP server
    if method != "tools/call":
        return await _forward(body, req_id)

    # Extract tool call context
    params       = body.get("params", {})
    tool_name    = params.get("name", "")
    tool_args    = params.get("arguments", {})
    triggered_by = request.headers.get("x-triggered-by", "")
    reason       = request.headers.get("x-reason", "")

    log.info(
        f"Intercepted: tool={tool_name}  agent={AGENT_ID}  "
        f"tenant={TENANT_ID}  triggered_by='{triggered_by}'"
    )

    # Create MCPToolInvocation CR — Kyverno admission webhook fires here
    cr_result = create_invocation_cr(tool_name, tool_args, triggered_by, reason)

    if not cr_result.get("admitted") and not cr_result.get("simulated"):
        policy_msg = cr_result.get("reason", "Tool invocation denied by policy")
        log.warning(f"BLOCKED: {tool_name} — {policy_msg}")
        return JSONResponse(
            content=jsonrpc_error(req_id, -32603, f"[AuthZ Policy Violation] {policy_msg}")
        )

    # CR admitted — forward to real MCP server
    log.info(f"ALLOWED: {tool_name} — forwarding to kubernetes-mcp-server")
    return await _forward(body, req_id)


@app.get("/mcp")
async def proxy_mcp_get(request: Request):
    """SSE endpoint — proxied directly to kubernetes-mcp-server."""
    return await _forward_sse(request)


@app.get("/healthz")
async def healthz():
    return {
        "status":  "ok",
        "proxy":   "mcp-authz-proxy",
        "tenant":  TENANT_ID,
        "agent":   AGENT_ID,
    }


@app.get("/stats")
async def stats():
    return {
        "mcp_server_url": MCP_SERVER_URL,
        "tenant_id":      TENANT_ID,
        "agent_id":       AGENT_ID,
        "k8s_available":  K8S_AVAILABLE,
        "timestamp":      datetime.now(timezone.utc).isoformat(),
    }

# ── Internal forwarding ───────────────────────────────────────────────────────

async def _forward(body: dict, req_id) -> JSONResponse:
    """
    Forward a JSON-RPC POST to kubernetes-mcp-server and return JSON.

    kubernetes-mcp-server uses MCP Streamable HTTP — it may respond with
    either plain JSON (application/json) or SSE (text/event-stream).
    Both are handled here.
    """
    async with httpx.AsyncClient(timeout=30.0) as client_:
        try:
            resp = await client_.post(
                f"{MCP_SERVER_URL}/mcp",
                json=body,
                headers={
                    "Content-Type": "application/json",
                    # Request JSON — server may still return SSE, handle both below
                    "Accept": "application/json, text/event-stream",
                },
            )
        except httpx.ConnectError as e:
            log.error(f"Cannot reach MCP server at {MCP_SERVER_URL}: {e}")
            return JSONResponse(
                content=jsonrpc_error(req_id, -32603, f"MCP server unreachable: {MCP_SERVER_URL}"),
                status_code=502,
            )
        except httpx.TimeoutException:
            log.error("MCP server request timed out")
            return JSONResponse(
                content=jsonrpc_error(req_id, -32603, "MCP server request timed out"),
                status_code=504,
            )

    content_type = resp.headers.get("content-type", "")
    log.debug(f"MCP server response: status={resp.status_code}  content-type={content_type}")

    # ── SSE response ──────────────────────────────────────────────────────────
    # kubernetes-mcp-server returns text/event-stream for tool calls.
    # Parse the first data event and return it as JSON.
    if "text/event-stream" in content_type:
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                data = line[5:].strip()
                if data:
                    try:
                        parsed = json.loads(data)
                        log.debug(f"SSE parsed OK: {str(parsed)[:120]}")
                        return JSONResponse(content=parsed)
                    except json.JSONDecodeError:
                        log.warning(f"SSE data line not valid JSON: {data[:100]}")
                        continue

        log.warning("SSE response had no parseable data lines")
        return JSONResponse(
            content=jsonrpc_error(req_id, -32603, "Empty SSE response from MCP server"),
            status_code=502,
        )

    # ── Empty body ────────────────────────────────────────────────────────────
    if not resp.content:
        log.warning(f"Empty body from MCP server (HTTP {resp.status_code})")
        return JSONResponse(
            content=jsonrpc_error(
                req_id, -32603,
                f"Empty response from MCP server (HTTP {resp.status_code})"
            ),
            status_code=502,
        )

    # ── Plain JSON ────────────────────────────────────────────────────────────
    try:
        return JSONResponse(content=resp.json())
    except json.JSONDecodeError:
        log.warning(f"Non-JSON response from MCP server: {resp.text[:200]}")
        return JSONResponse(
            content=jsonrpc_error(
                req_id, -32603,
                f"Non-JSON response from MCP server: {resp.text[:200]}"
            ),
            status_code=502,
        )


async def _forward_sse(request: Request) -> StreamingResponse:
    """Forward GET SSE stream from upstream kubernetes-mcp-server."""
    async def event_stream():
        async with httpx.AsyncClient(timeout=None) as client_:
            headers = {
                k: v for k, v in request.headers.items()
                if k.lower() not in ("host",)
            }
            async with client_.stream(
                "GET", f"{MCP_SERVER_URL}/mcp", headers=headers
            ) as resp:
                async for chunk in resp.aiter_bytes():
                    yield chunk

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info(f"MCP AuthZ Proxy starting on :{PROXY_PORT}")
    log.info(f"Upstream MCP server : {MCP_SERVER_URL}")
    log.info(f"Tenant: {TENANT_ID}  |  Agent: {AGENT_ID}")
    log.info(f"Kubernetes enforcement: {'ENABLED' if K8S_AVAILABLE else 'SIMULATED (no kubeconfig)'}")
    uvicorn.run(app, host="0.0.0.0", port=PROXY_PORT)