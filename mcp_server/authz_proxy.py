"""
MCP AuthZ Proxy
───────────────
Enforcement bridge between AI agents and kubernetes-mcp-server.
Intercepts every tool call, creates an MCPToolInvocation CR,
lets Kyverno admit or deny it, then forwards or blocks.

Flow:
  Agent → AuthZ Proxy (:8090) → MCPToolInvocation CR → Kyverno Webhook
                                                           ↓
                                                     ALLOW / DENY
                                                           ↓
                                           kubernetes-mcp-server (:8080)
                                                           ↓
                                                  Kubernetes API
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse
import uvicorn

# Kubernetes client — optional if running outside cluster
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
AGENT_ID       = os.environ.get("AGENT_ID", "sre-agent")   # pod-level default
MCP_GROUP      = "mcp.security.io"
MCP_VERSION    = "v1alpha1"
MCP_PLURAL     = "mcptoolinvocations"

app = FastAPI(title="MCP AuthZ Proxy", version="1.0.0")

# ── Kubernetes CR helpers ─────────────────────────────────────────────────────

def create_invocation_cr(
    tool_name:    str,
    params:       dict,
    triggered_by: str,
    reason:       str,
    agent_id:     str = None,
    tenant_id:    str = None,   # explicit tenant from x-tenant-id header
) -> dict:
    """
    Create an MCPToolInvocation CR and let Kyverno evaluate it.
    Returns {"admitted": True/False, ...}
    """
    if not K8S_AVAILABLE:
        log.warning("K8s client not available — simulating CR creation")
        return {"simulated": True, "admitted": True}

    effective_agent_id = agent_id or AGENT_ID

    # Tenant detection priority:
    # 1. tenant_id param (from x-tenant-id header — explicit override)
    # 2. params.namespace (auto-detect cross-namespace tool calls)
    # 3. TENANT_ID env var (default — same tenant)
    if tenant_id and tenant_id != TENANT_ID:
        effective_tenant_id = tenant_id
    else:
        target_ns = params.get("namespace", "")
        effective_tenant_id = target_ns if (target_ns and target_ns != TENANT_ID) else TENANT_ID

    custom_api = client.CustomObjectsApi()
    name = f"proxy-{tool_name.replace('_', '-')}-{uuid.uuid4().hex[:6]}"

    body = {
        "apiVersion": f"{MCP_GROUP}/{MCP_VERSION}",
        "kind": "MCPToolInvocation",
        "metadata": {
            "name":      name,
            "namespace": TENANT_ID,
            "annotations": {},
            "labels": {
                "mcp.security.io/agent-id":  effective_agent_id,
                "mcp.security.io/tool-name": tool_name,
            },
        },
        "spec": {
            "toolName":    tool_name,
            "agentId":     effective_agent_id,
            "tenantId":    effective_tenant_id,   # ← target namespace, not always TENANT_ID
            "triggeredBy": triggered_by,
            "reason":      reason,
            "parameters":  params,
        },
    }

    try:
        result = custom_api.create_namespaced_custom_object(
            group=MCP_GROUP, version=MCP_VERSION,
            namespace=TENANT_ID, plural=MCP_PLURAL, body=body,
        )
        log.info(f"CR admitted: {name}  tool={tool_name}  agent={effective_agent_id}")
        return {"admitted": True, "name": name, "cr": result}

    except client.ApiException as e:
        # 400 — Kyverno ValidatingPolicy (policies.kyverno.io/v1) denial
        # 403 — Kyverno ClusterPolicy (kyverno.io/v1) denial
        # 422 — Unprocessable entity
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

# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/mcp")
async def proxy_mcp_post(request: Request):
    """
    Intercepts MCP tools/call requests.
    Non-tool-call methods pass through directly.
    tools/call → create MCPToolInvocation CR → Kyverno → forward or block.
    """
    body   = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")

    # Pass-through: initialize, tools/list, notifications, etc.
    if method != "tools/call":
        return await _forward(body, req_id)

    # Extract context from request
    params       = body.get("params", {})
    tool_name    = params.get("name", "")
    tool_args    = params.get("arguments", {})
    triggered_by = request.headers.get("x-triggered-by", "")
    reason       = request.headers.get("x-reason", "")
    agent_id     = request.headers.get("x-agent-id", AGENT_ID)
    tenant_id    = request.headers.get("x-tenant-id", "")   # explicit tenant override

    log.info(
        f"Intercepted: tool={tool_name}  agent={agent_id}  "
        f"tenant={tenant_id or TENANT_ID}  triggered_by='{triggered_by}'"
    )

    # Create CR — Kyverno admission webhook fires here
    cr_result = create_invocation_cr(tool_name, tool_args, triggered_by, reason, agent_id, tenant_id)

    if not cr_result.get("admitted") and not cr_result.get("simulated"):
        policy_msg = cr_result.get("reason", "Tool invocation denied by policy")
        log.warning(f"BLOCKED: {tool_name} — {policy_msg}")
        return JSONResponse(
            content=jsonrpc_error(req_id, -32603, f"[AuthZ Policy Violation] {policy_msg}")
        )

    log.info(f"ALLOWED: {tool_name} — forwarding to kubernetes-mcp-server")
    return await _forward(body, req_id)


@app.get("/mcp")
async def proxy_mcp_get(request: Request):
    """SSE GET stream — proxied directly to kubernetes-mcp-server."""
    return await _forward_sse(request)


@app.get("/healthz")
async def healthz():
    return {
        "status": "ok",
        "proxy":  "mcp-authz-proxy",
        "tenant": TENANT_ID,
        "agent":  AGENT_ID,
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
    Forward JSON-RPC POST to kubernetes-mcp-server.
    Handles three response types:
      1. text/event-stream (SSE) — parse first data event
      2. Empty body            — return JSON-RPC error
      3. Plain JSON            — return as-is, handle error notifications
    """
    async with httpx.AsyncClient(timeout=30.0) as c:
        try:
            resp = await c.post(
                f"{MCP_SERVER_URL}/mcp",
                json=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept":       "application/json, text/event-stream",
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
    log.debug(f"MCP server response: status={resp.status_code}  ct={content_type}")

    # ── SSE response ──────────────────────────────────────────────────────────
    if "text/event-stream" in content_type:
        for line in resp.text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if not data:
                continue
            try:
                parsed = json.loads(data)
                # Skip server-sent notifications (no id field)
                if "method" in parsed and "id" not in parsed:
                    log.debug(f"SSE notification skipped: {parsed.get('method')}")
                    # If it's an error notification, surface it
                    if parsed.get("params", {}).get("level") == "error":
                        err = parsed.get("params", {}).get("data", "MCP server error")
                        log.warning(f"MCP SSE error notification: {err}")
                        return JSONResponse(
                            content=jsonrpc_error(req_id, -32603, f"MCP server error: {err}")
                        )
                    continue
                log.debug(f"SSE result: {str(parsed)[:120]}")
                return JSONResponse(content=parsed)
            except json.JSONDecodeError:
                continue

        log.warning("SSE response had no parseable result")
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
        result = resp.json()

        # MCP server sends notifications/message as plain JSON for errors
        # e.g. RBAC permission denied, resource not found
        if (
            "method" in result
            and result.get("method") == "notifications/message"
            and result.get("params", {}).get("level") == "error"
        ):
            err = result.get("params", {}).get("data", "MCP server error")
            log.warning(f"MCP server error notification: {err}")
            return JSONResponse(
                content=jsonrpc_error(req_id, -32603, f"MCP server error: {err}")
            )

        return JSONResponse(content=result)

    except json.JSONDecodeError:
        log.warning(f"Non-JSON response: {resp.text[:200]}")
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
        async with httpx.AsyncClient(timeout=None) as c:
            headers = {
                k: v for k, v in request.headers.items()
                if k.lower() not in ("host",)
            }
            async with c.stream("GET", f"{MCP_SERVER_URL}/mcp", headers=headers) as resp:
                async for chunk in resp.aiter_bytes():
                    yield chunk

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info(f"MCP AuthZ Proxy starting on :{PROXY_PORT}")
    log.info(f"Upstream MCP server : {MCP_SERVER_URL}")
    log.info(f"Tenant: {TENANT_ID}  |  Default Agent: {AGENT_ID}")
    log.info(f"K8s enforcement: {'ENABLED' if K8S_AVAILABLE else 'SIMULATED'}")
    uvicorn.run(app, host="0.0.0.0", port=PROXY_PORT)