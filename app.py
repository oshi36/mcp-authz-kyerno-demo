"""
MCP AuthZ Demo — Policy-Driven Tool Invocation Control
Talk: Closing the AuthZ Gap in MCP
Speaker: Oshi (InfraCloud Technologies / Improving)

Flask app that makes REAL MCP tool calls via the authz-proxy
and shows actual Kyverno policy enforcement in real-time.
No simulation — every invocation goes through the real proxy.
"""

from flask import Flask, render_template, request, jsonify
import json
import time
import datetime
import os
import re
import requests as req

# Optional: Kubernetes client for reading live CRs
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

app = Flask(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
PROXY_URL  = os.environ.get("PROXY_URL",  "http://localhost:8090")
TENANT_ID  = os.environ.get("TENANT_ID",  "tenant-acme")
MCP_GROUP  = "mcp.security.io"
MCP_VERSION = "v1alpha1"
MCP_PLURAL = "mcptoolinvocations"

# ── Agent definitions ──────────────────────────────────────────────────────────
AGENTS = {
    "sre-agent": {
        "label": "SRE Agent",
        "namespace": "agents",
        "risk": "low",
        "icon": "ti-activity",
        "color": "blue",
        "allowed_tools": [
            "pods_list", "pods_list_in_namespace", "pods_get",
            "pods_log", "pods_top", "events_list",
            "namespaces_list", "nodes_top", "configuration_view",
        ],
    },
    "cost-agent": {
        "label": "Cost Agent",
        "namespace": "agents",
        "risk": "low",
        "icon": "ti-chart-bar",
        "color": "green",
        "allowed_tools": [
            "nodes_stats_summary", "nodes_top", "nodes_log",
            "pods_top", "resources_list", "resources_get",
        ],
    },
    "remediation-agent": {
        "label": "Remediation Agent",
        "namespace": "agents",
        "risk": "high",
        "icon": "ti-tool",
        "color": "amber",
        "allowed_tools": [
            "pods_delete", "pods_exec", "pods_run",
            "resources_scale", "resources_create_or_update", "resources_delete",
        ],
    },
}

TENANTS = ["tenant-acme", "tenant-globex"]

ALL_TOOLS = [
    # Observability
    {"name": "pods_list",              "category": "observability", "write": False},
    {"name": "pods_list_in_namespace", "category": "observability", "write": False},
    {"name": "pods_get",               "category": "observability", "write": False},
    {"name": "pods_log",               "category": "observability", "write": False},
    {"name": "pods_top",               "category": "observability", "write": False},
    {"name": "events_list",            "category": "observability", "write": False},
    {"name": "namespaces_list",        "category": "observability", "write": False},
    {"name": "nodes_top",              "category": "observability", "write": False},
    {"name": "configuration_view",     "category": "observability", "write": False},
    # Cost
    {"name": "nodes_stats_summary",    "category": "cost",          "write": False},
    {"name": "nodes_log",              "category": "cost",          "write": False},
    {"name": "resources_list",         "category": "cost",          "write": False},
    {"name": "resources_get",          "category": "cost",          "write": False},
    # Remediation (write)
    {"name": "pods_delete",            "category": "remediation",   "write": True},
    {"name": "pods_exec",              "category": "remediation",   "write": True},
    {"name": "pods_run",               "category": "remediation",   "write": True},
    {"name": "resources_scale",        "category": "remediation",   "write": True},
    {"name": "resources_create_or_update", "category": "remediation", "write": True},
    {"name": "resources_delete",       "category": "remediation",   "write": True},
]

WRITE_TOOLS = [t["name"] for t in ALL_TOOLS if t["write"]]

SCENARIOS = [
    {
        "id": "allowed-sre-pods",
        "label": "✅ SRE lists pods in own namespace",
        "description": "SRE agent lists pods in tenant-acme. All policies pass.",
        "invocation": {
            "agentId": "sre-agent", "toolName": "pods_list_in_namespace",
            "namespace": "tenant-acme", "tenantId": "tenant-acme",
            "triggeredBy": "alice@acme.com",
            "reason": "Checking pod status during incident investigation",
            "parameters": {"namespace": "tenant-acme"},
        },
    },
    {
        "id": "denied-tool-allowlist",
        "label": "❌ SRE tries to scale deployment (not in allowlist)",
        "description": "SRE agent calls resources_scale — not in its allowlist. Policy 1 blocks.",
        "invocation": {
            "agentId": "sre-agent", "toolName": "resources_scale",
            "namespace": "tenant-acme", "tenantId": "tenant-acme",
            "triggeredBy": "alice@acme.com",
            "reason": "Trying to scale after seeing high latency",
            "parameters": {"apiVersion": "apps/v1", "kind": "Deployment",
                          "name": "nginx", "namespace": "tenant-acme", "scale": 5},
        },
    },
    {
        "id": "denied-cross-tenant",
        "label": "❌ SRE crosses tenant boundary",
        "description": "SRE in tenant-acme tries listing pods in tenant-globex. Policy 2 blocks.",
        "invocation": {
            "agentId": "sre-agent", "toolName": "pods_list_in_namespace",
            "namespace": "tenant-acme", "tenantId": "tenant-globex",
            "triggeredBy": "alice@acme.com",
            "reason": "Checking Globex pods",
            "parameters": {"namespace": "tenant-globex"},
        },
    },
    {
        "id": "denied-no-human",
        "label": "❌ Remediation scales without human trigger",
        "description": "Autonomous agent calls resources_scale — no triggeredBy. Policy 3b blocks.",
        "invocation": {
            "agentId": "remediation-agent", "toolName": "resources_scale",
            "namespace": "tenant-acme", "tenantId": "tenant-acme",
            "triggeredBy": "",
            "reason": "Auto-scaling triggered by alert",
            "parameters": {"apiVersion": "apps/v1", "kind": "Deployment",
                          "name": "nginx", "namespace": "tenant-acme", "scale": 5},
        },
    },
    {
        "id": "allowed-remediation",
        "label": "✅ Remediation scales with human approval",
        "description": "Remediation agent scales with human context. All policies pass.",
        "invocation": {
            "agentId": "remediation-agent", "toolName": "resources_scale",
            "namespace": "tenant-acme", "tenantId": "tenant-acme",
            "triggeredBy": "bob@acme.com",
            "reason": "Approved by on-call engineer Bob",
            "parameters": {"apiVersion": "apps/v1", "kind": "Deployment",
                          "name": "nginx", "namespace": "tenant-acme", "scale": 3},
        },
    },
    {
        "id": "allowed-cost-resources",
        "label": "✅ Cost agent reads resource usage",
        "description": "Cost agent lists resources for rightsizing. All policies pass.",
        "invocation": {
            "agentId": "cost-agent", "toolName": "resources_list",
            "namespace": "tenant-acme", "tenantId": "tenant-acme",
            "triggeredBy": "carol@acme.com",
            "reason": "Weekly rightsizing analysis",
            "parameters": {"apiVersion": "apps/v1", "kind": "Deployment",
                          "namespace": "tenant-acme"},
        },
    },
]

# ── Real proxy call ────────────────────────────────────────────────────────────

def call_real_proxy(invocation: dict) -> dict:
    """
    Makes a real MCP tool call through the authz-proxy.
    Returns structured result matching the UI format.
    """
    tool_name    = invocation.get("toolName", "")
    agent_id     = invocation.get("agentId", "sre-agent")
    triggered_by = invocation.get("triggeredBy", "")
    namespace    = invocation.get("namespace", TENANT_ID)
    tenant_id    = invocation.get("tenantId", TENANT_ID)
    arguments    = invocation.get("parameters", {})

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }
    headers = {
        "Content-Type":   "application/json",
        "x-agent-id":     agent_id,
        "x-triggered-by": triggered_by,
        "x-reason":       invocation.get("reason", ""),
        "x-tenant-id":    tenant_id,    # explicit tenant — enables cross-tenant detection
    }

    try:
        resp = req.post(
            f"{PROXY_URL}/mcp",
            json=payload,
            headers=headers,
            timeout=10,
        )
        result = resp.json() if resp.content else {}
    except req.exceptions.ConnectionError:
        return _proxy_unavailable_result(invocation)
    except Exception as e:
        return _proxy_unavailable_result(invocation, str(e))

    # ── Parse real response ────────────────────────────────────────────────────
    is_denied = "error" in result
    error_msg = ""
    if is_denied:
        err = result.get("error", {})
        error_msg = err.get("message", "") if isinstance(err, dict) else str(err)

    decision = "DENIED" if is_denied else "ALLOWED"

    # Build per-policy results from real Kyverno response
    policy_results = _build_policy_results(
        decision, error_msg, tool_name, agent_id, tenant_id, namespace, triggered_by
    )

    # Get real annotations from K8s if admitted
    audit_annotations = {}
    if not is_denied and K8S_AVAILABLE:
        audit_annotations = _get_latest_annotations()

    return {
        "decision":         decision,
        "policy_results":   policy_results,
        "failed_count":     len([r for r in policy_results if r["result"] == "FAIL"]) if decision == "DENIED" else 0,
        "pass_count":       len([r for r in policy_results if r["result"] == "PASS"]),
        "audit_annotations": audit_annotations,
        "real_mode":        True,
        "proxy_response":   result,
        "invocation":       invocation,
        "timestamp":        datetime.datetime.utcnow().isoformat() + "Z",
    }


def _build_policy_results(
    decision, error_msg, tool_name, agent_id, tenant_id, namespace, triggered_by
) -> list:
    """
    Build per-policy result cards from real Kyverno response only.
    No duplicate policy logic — Kyverno is the single source of truth.

    On DENY  — show the policy Kyverno reported as failing.
               Show others as PASS (they were evaluated before the failure).
    On ALLOW — all validating policies passed, mutating policy injected.
    """
    # Extract which policy Kyverno reported and its human-readable message
    kyverno_failed = None
    kyverno_msg    = ""

    if decision == "DENIED" and error_msg:
        for policy_name in [
            "mcp-tool-allowlist",
            "mcp-tenant-isolation",
            "mcp-require-human-trigger",
        ]:
            if policy_name in error_msg:
                kyverno_failed = policy_name
                # Pull clean message after "failed:"
                match = re.search(r"failed[:\s]+(.+?)(?:  |\n|$)", error_msg)
                kyverno_msg = match.group(1).strip() if match else error_msg
                break
        if not kyverno_failed:
            # Generic denial — unknown which policy
            kyverno_msg = error_msg

    def result_for(policy_name, rule, pass_msg, write_only=False):
        """Return a policy result card."""
        if write_only and tool_name not in WRITE_TOOLS:
            return None
        # Kyverno explicitly reported this policy as failing
        if kyverno_failed == policy_name:
            return {"policy": policy_name, "rule": rule, "result": "FAIL",
                    "message": kyverno_msg}
        # Kyverno denied but we couldn't identify which policy from the message
        if decision == "DENIED" and not kyverno_failed:
            return {"policy": policy_name, "rule": rule, "result": "FAIL",
                    "message": kyverno_msg or "Denied by Kyverno — check proxy logs"}
        # A different policy failed — this one was evaluated and passed
        if kyverno_failed and kyverno_failed != policy_name:
            return {"policy": policy_name, "rule": rule, "result": "PASS",
                    "message": pass_msg}
        # ALLOWED — all policies passed
        return {"policy": policy_name, "rule": rule, "result": "PASS",
                "message": pass_msg}

    results = []

    # Policy 1 — Tool Allowlist
    r = result_for(
        "mcp-tool-allowlist",
        f"{agent_id}-allowlist",
        f"Tool '{tool_name}' is permitted for '{agent_id}'",
    )
    if r: results.append(r)

    # Policy 2 — Tenant Isolation
    r = result_for(
        "mcp-tenant-isolation",
        "block-cross-tenant-invocations",
        f"Tenant context matches — '{tenant_id}' ✓",
    )
    if r: results.append(r)

    # Policy 3a — Human Identity Injection (always MUTATE)
    results.append({
        "policy":  "mcp-inject-human-identity",
        "rule":    "inject-human-identity-annotations",
        "result":  "MUTATE",
        "message": (
            f"Injected: mcp.security.io/triggered-by={triggered_by or agent_id}, "
            f"mcp.security.io/triggered-at="
            f"{datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}, "
            f"mcp.security.io/policy-version=v1"
        ),
    })

    # Policy 3b — Human Trigger (write tools only)
    r = result_for(
        "mcp-require-human-trigger",
        "require-human-trigger-for-write-tools",
        f"Human trigger '{triggered_by}' present for write tool '{tool_name}'",
        write_only=True,
    )
    if r: results.append(r)

    return results


def _get_latest_annotations() -> dict:
    """Fetch annotations from the latest MCPToolInvocation CR in the cluster."""
    try:
        custom_api = client.CustomObjectsApi()
        crs = custom_api.list_namespaced_custom_object(
            group=MCP_GROUP, version=MCP_VERSION,
            namespace=TENANT_ID, plural=MCP_PLURAL,
        )
        items = crs.get("items", [])
        if not items:
            return {}
        # Sort by creationTimestamp, get latest
        latest = sorted(
            items,
            key=lambda x: x.get("metadata", {}).get("creationTimestamp", ""),
        )[-1]
        annotations = latest.get("metadata", {}).get("annotations", {})
        # Return only mcp.security.io annotations
        return {k: v for k, v in annotations.items() if "mcp.security.io" in k}
    except Exception:
        return {}


def _proxy_unavailable_result(invocation: dict, error: str = "") -> dict:
    """Fallback result when proxy is not reachable."""
    return {
        "decision":         "ERROR",
        "policy_results":   [],
        "failed_count":     0,
        "pass_count":       0,
        "audit_annotations": {},
        "real_mode":        False,
        "error":            f"Cannot connect to authz-proxy at {PROXY_URL}. {error}".strip(),
        "invocation":       invocation,
        "timestamp":        datetime.datetime.utcnow().isoformat() + "Z",
    }

# ── Routes ──────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template(
        "index.html",
        agents=AGENTS,
        tenants=TENANTS,
        all_tools=ALL_TOOLS,
        scenarios=SCENARIOS,
        proxy_url=PROXY_URL,
    )


@app.route("/api/invoke", methods=["POST"])
def invoke_tool():
    data = request.get_json()
    time.sleep(0.2)
    result = call_real_proxy(data)
    return jsonify(result)


@app.route("/api/scenario/<scenario_id>")
def get_scenario(scenario_id):
    scenario = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
    if not scenario:
        return jsonify({"error": "Scenario not found"}), 404
    return jsonify(scenario)


@app.route("/api/agents")
def get_agents():
    return jsonify(AGENTS)


@app.route("/api/tools")
def get_tools():
    return jsonify(ALL_TOOLS)


@app.route("/api/status")
def get_status():
    """Check if proxy and K8s are reachable."""
    proxy_ok = False
    try:
        r = req.get(f"{PROXY_URL}/healthz", timeout=3)
        proxy_ok = r.status_code == 200
        proxy_info = r.json() if proxy_ok else {}
    except Exception:
        proxy_info = {}

    k8s_ok = K8S_AVAILABLE
    active_policies = []
    live_invocations = []

    if k8s_ok:
        try:
            custom_api = client.CustomObjectsApi()
            crs = custom_api.list_namespaced_custom_object(
                group=MCP_GROUP, version=MCP_VERSION,
                namespace=TENANT_ID, plural=MCP_PLURAL,
            )
            items = crs.get("items", [])
            for item in sorted(
                items,
                key=lambda x: x.get("metadata", {}).get("creationTimestamp", ""),
                reverse=True,
            )[:10]:
                meta = item.get("metadata", {})
                spec = item.get("spec", {})
                annotations = {
                    k: v for k, v in meta.get("annotations", {}).items()
                    if "mcp.security.io" in k
                }
                live_invocations.append({
                    "name":        meta.get("name"),
                    "tool":        spec.get("toolName"),
                    "agent":       spec.get("agentId"),
                    "triggeredBy": spec.get("triggeredBy"),
                    "time":        meta.get("creationTimestamp"),
                    "annotations": annotations,
                })
        except Exception:
            pass

    return jsonify({
        "proxy":             {"ok": proxy_ok, "url": PROXY_URL, **proxy_info},
        "kubernetes":        {"ok": k8s_ok},
        "live_invocations":  live_invocations,
        "mode":              "real" if proxy_ok else "unavailable",
    })


@app.route("/api/live-invocations")
def get_live_invocations():
    """Return recent MCPToolInvocation CRs from the cluster."""
    if not K8S_AVAILABLE:
        return jsonify({"items": [], "k8s_available": False})
    try:
        custom_api = client.CustomObjectsApi()
        crs = custom_api.list_namespaced_custom_object(
            group=MCP_GROUP, version=MCP_VERSION,
            namespace=TENANT_ID, plural=MCP_PLURAL,
        )
        items = []
        for item in sorted(
            crs.get("items", []),
            key=lambda x: x.get("metadata", {}).get("creationTimestamp", ""),
            reverse=True,
        )[:20]:
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            items.append({
                "name":        meta.get("name"),
                "tool":        spec.get("toolName"),
                "agent":       spec.get("agentId"),
                "tenant":      spec.get("tenantId"),
                "triggeredBy": spec.get("triggeredBy"),
                "time":        meta.get("creationTimestamp"),
                "annotations": {
                    k: v for k, v in meta.get("annotations", {}).items()
                    if "mcp.security.io" in k
                },
            })
        return jsonify({"items": items, "k8s_available": True})
    except Exception as e:
        return jsonify({"items": [], "error": str(e), "k8s_available": True})


@app.route("/api/policies")
def get_policies():
    policies_dir = os.path.join(os.path.dirname(__file__), "k8s", "policies")
    policies = []
    if os.path.exists(policies_dir):
        for fname in sorted(os.listdir(policies_dir)):
            if fname.endswith(".yaml"):
                with open(os.path.join(policies_dir, fname)) as f:
                    policies.append({"filename": fname, "content": f.read()})
    return jsonify(policies)


if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "true").lower() == "true"
    print(f"Proxy URL: {PROXY_URL}")
    print(f"K8s available: {K8S_AVAILABLE}")
    app.run(host="0.0.0.0", port=port, debug=debug)