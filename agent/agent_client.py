"""
Demo Agent Client
─────────────────
A minimal AI agent that connects to the kubernetes-mcp-server via
the authz-proxy and sends real MCP tool calls. Used during the talk
to show live policy enforcement from the agent's perspective.

The agent connects to:
  http://mcp-server.tenant-acme:8090/mcp   ← authz-proxy (Kyverno-gated)
  NOT:
  http://mcp-server.tenant-acme:8080/mcp   ← direct mcp-server (bypasses policy)

Usage:
  kubectl port-forward -n tenant-acme svc/mcp-server 8090:8090
  python agent_client.py

  python agent_client.py --single list-pods
  python agent_client.py --single delete-pod
  python agent_client.py --single cross-tenant
  python agent_client.py --single scale-no-human
  AGENT_ID=remediation-agent TRIGGERED_BY=bob@acme.com python agent_client.py --single scale
"""

import httpx
import json
import os
import sys
import asyncio

PROXY_URL    = os.environ.get("PROXY_URL",    "http://localhost:8090")
TRIGGERED_BY = os.environ.get("TRIGGERED_BY", "alice@acme.com")
AGENT_ID     = os.environ.get("AGENT_ID",     "sre-agent")

# ── MCP JSON-RPC helpers ──────────────────────────────────────────────────────

async def mcp_call(
    tool_name:    str,
    arguments:    dict,
    reason:       str = "",
    triggered_by: str | None = None,
) -> dict:
    """
    Send a tools/call JSON-RPC request to the authz-proxy.
    The proxy intercepts this, creates an MCPToolInvocation CR,
    lets Kyverno evaluate it, then forwards or blocks.
    """
    payload = {
        "jsonrpc": "2.0",
        "id":      1,
        "method":  "tools/call",
        "params": {
            "name":      tool_name,
            "arguments": arguments,
        },
    }
    headers = {
        "Content-Type":   "application/json",
        "x-triggered-by": triggered_by if triggered_by is not None else TRIGGERED_BY,
        "x-reason":       reason,
        "x-agent-id":     AGENT_ID,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.post(f"{PROXY_URL}/mcp", json=payload, headers=headers)

            if not resp.content:
                return {"error": {"message": f"Empty response from proxy (HTTP {resp.status_code})"}}

            try:
                return resp.json()
            except json.JSONDecodeError:
                return {"error": {"message": f"Non-JSON response: {resp.text[:200]}"}}

        except httpx.ConnectError:
            return {"error": {"message": f"Cannot connect to proxy at {PROXY_URL}. Is port-forward running?"}}
        except httpx.TimeoutException:
            return {"error": {"message": "Request timed out after 15s"}}


# ── Pretty printer ────────────────────────────────────────────────────────────

def print_result(scenario: str, tool: str, result: dict):
    print(f"\n{'─' * 60}")
    print(f"  Scenario : {scenario}")
    print(f"  Tool     : {tool}")

    if "error" in result:
        msg = result["error"]
        if isinstance(msg, dict):
            msg = msg.get("message", str(msg))

        if "[AuthZ Policy Violation]" in str(msg) or "denied" in str(msg).lower():
            print(f"  Decision : ❌  DENIED BY KYVERNO")
            print(f"  Reason   : {msg}")
        else:
            print(f"  Decision : ⚠️  ERROR")
            print(f"  Detail   : {msg}")

    elif "result" in result:
        print(f"  Decision : ✅  ALLOWED — forwarded to kubernetes-mcp-server")
        content = result["result"].get("content", [])
        if content:
            text = content[0].get("text", "")
            print(f"  Response : {text[:200]}{'...' if len(text) > 200 else ''}")
        else:
            print(f"  Response : (empty result)")
    else:
        print(f"  Raw      : {json.dumps(result, indent=2)[:300]}")

    print(f"{'─' * 60}")


# ── Demo scenarios ────────────────────────────────────────────────────────────

async def run_demo():
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║  MCP AuthZ Demo — Agent Client                           ║")
    print(f"║  Proxy : {PROXY_URL:<48}║")
    print(f"║  Agent : {AGENT_ID:<48}║")
    print(f"║  Human : {TRIGGERED_BY:<48}║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    print("▶ Connected to authz-proxy. Running 4 scenarios...\n")

    # ── Scenario 1: ALLOWED ───────────────────────────────────────────────────
    # sre-agent lists pods in own namespace — in allowlist, tenant matches
    print("  [1/4] SRE lists pods in own namespace")
    result = await mcp_call(
        tool_name="pods_list_in_namespace",
        arguments={"namespace": "tenant-acme"},
        reason="SRE checking pod status for incident investigation",
    )
    print_result(
        "✅ SRE lists pods in own namespace",
        "pods_list_in_namespace",
        result,
    )

    await asyncio.sleep(0.5)

    # ── Scenario 2: DENIED — tool not in allowlist ────────────────────────────
    # sre-agent tries pods_delete — only remediation-agent can delete
    print("\n  [2/4] SRE tries to delete a pod")
    result = await mcp_call(
        tool_name="pods_delete",
        arguments={"name": "checkout-abc", "namespace": "tenant-acme"},
        reason="SRE trying to remove a crashed pod",
    )
    print_result(
        "❌ SRE tries pods_delete (not in allowlist)",
        "pods_delete",
        result,
    )

    await asyncio.sleep(0.5)

    # ── Scenario 3: DENIED — cross-tenant ────────────────────────────────────
    # sre-agent in tenant-acme queries tenant-globex namespace
    # Policy 02: tenantId must match the CR namespace
    print("\n  [3/4] SRE queries a different tenant's namespace")
    result = await mcp_call(
        tool_name="pods_list_in_namespace",
        arguments={"namespace": "tenant-globex"},
        reason="Accidentally querying wrong namespace",
    )
    print_result(
        "❌ SRE queries tenant-globex (cross-tenant blocked)",
        "pods_list_in_namespace  namespace=tenant-globex",
        result,
    )

    await asyncio.sleep(0.5)

    # ── Scenario 4: DENIED — write tool without human trigger ────────────────
    # resources_scale is a write tool — requires triggeredBy (Policy 3b)
    # triggered_by="" explicitly simulates autonomous agent
    print("\n  [4/4] Autonomous agent calls a write tool (no human trigger)")
    result = await mcp_call(
        tool_name="resources_scale",
        arguments={
            "apiVersion": "apps/v1",
            "kind":       "Deployment",
            "name":       "checkout",
            "namespace":  "tenant-acme",
            "scale":      5,              # ← correct param name
        },
        reason="Auto-scaling triggered by metric alert",
        triggered_by="",
    )
    print_result(
        "❌ Write tool with no human trigger",
        "resources_scale  (triggered_by=empty)",
        result,
    )

    # ── Scenario 5 hint ──────────────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print("  Scenario 5 — remediation-agent with human approval:")
    print("    AGENT_ID=remediation-agent TRIGGERED_BY=bob@acme.com \\")
    print("    python agent_client.py --single scale")
    print(f"{'─' * 60}")

    print("\n✅ Demo complete.\n")
    print("  Individual scenarios:")
    print("    python agent_client.py --single list-pods")
    print("    python agent_client.py --single delete-pod")
    print("    python agent_client.py --single cross-tenant")
    print("    python agent_client.py --single scale-no-human")
    print("    AGENT_ID=remediation-agent TRIGGERED_BY=bob@acme.com \\")
    print("    python agent_client.py --single scale")
    print()


# ── Single scenario runner ────────────────────────────────────────────────────

async def run_single(scenario: str):
    scenarios = {
        # ✅ sre-agent reads pods in own namespace — ALLOWED
        "list-pods": lambda: mcp_call(
            "pods_list_in_namespace",
            {"namespace": "tenant-acme"},
            "Checking pod status",
        ),
        # ❌ sre-agent tries delete — not in allowlist
        "delete-pod": lambda: mcp_call(
            "pods_delete",
            {"name": "checkout-abc", "namespace": "tenant-acme"},
            "Deleting crashed pod",
        ),
        # ❌ sre-agent queries tenant-globex — cross-tenant blocked
        "cross-tenant": lambda: mcp_call(
            "pods_list_in_namespace",
            {"namespace": "tenant-globex"},
            "Cross-tenant query",
        ),
        # ❌ resources_scale without human trigger — Policy 3b blocks
        "scale-no-human": lambda: mcp_call(
            "resources_scale",
            {
                "apiVersion": "apps/v1",
                "kind":       "Deployment",
                "name":       "checkout",
                "namespace":  "tenant-acme",
                "scale":      5,            # ← correct param name
            },
            "Autonomous scale attempt",
            triggered_by="",
        ),
        # ✅ remediation-agent + human trigger — ALLOWED
        # Run as: AGENT_ID=remediation-agent TRIGGERED_BY=bob@acme.com python agent_client.py --single scale
        "scale": lambda: mcp_call(
            "resources_scale",
            {
                "apiVersion": "apps/v1",
                "kind":       "Deployment",
                "name":       "checkout",
                "namespace":  "tenant-acme",
                "scale":      3,            # ← correct param name
            },
            "Human-approved scale",
        ),
        # ✅ sre-agent reads pod logs — ALLOWED
        "logs": lambda: mcp_call(
            "pods_log",
            {"name": "checkout-abc", "namespace": "tenant-acme"},
            "Checking logs for error",
        ),
        # ✅ sre-agent lists events — ALLOWED
        "events": lambda: mcp_call(
            "events_list",
            {},
            "Listing cluster events",
        ),
    }

    if scenario not in scenarios:
        print(f"Unknown scenario '{scenario}'.")
        print(f"Available: {', '.join(scenarios.keys())}")
        sys.exit(1)

    result = await scenarios[scenario]()
    print(json.dumps(result, indent=2))


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--single":
        asyncio.run(run_single(sys.argv[2]))
    else:
        asyncio.run(run_demo())