#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# MCP AuthZ Demo — Teardown Script
# Removes the full stack deployed by bootstrap.sh:
#   1. Kyverno ClusterPolicies
#   2. kubernetes-mcp-server Helm releases (per tenant)
#   3. AuthZ proxy deployment
#   4. MCPToolInvocation CRD (and all CRs)
#   5. Tenant namespaces + RBAC
#   6. Kyverno
#   7. kind cluster
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

CLUSTER_NAME="mcp-authz-demo"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   MCP AuthZ Demo — Teardown                              ║"
echo "║   Removing full stack from kind cluster                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Kyverno ClusterPolicies ──────────────────────────────────────────
echo "▶ Step 1: Removing Kyverno ClusterPolicies..."
sudo kubectl delete -f k8s/policies/03-human-identity.yaml --ignore-not-found
sudo kubectl delete -f k8s/policies/02-tenant-isolation.yaml --ignore-not-found
sudo kubectl delete -f k8s/policies/01-tool-allowlist.yaml --ignore-not-found
echo "  ✓ ClusterPolicies removed"

# ── Step 2: kubernetes-mcp-server Helm releases ───────────────────────────────
echo ""
echo "▶ Step 2: Uninstalling kubernetes-mcp-server Helm releases..."
sudo helm uninstall mcp-server-acme --namespace tenant-acme 2>/dev/null && echo "  ✓ mcp-server-acme uninstalled" || echo "  ℹ mcp-server-acme not found, skipping"
sudo helm uninstall mcp-server-globex --namespace tenant-globex 2>/dev/null && echo "  ✓ mcp-server-globex uninstalled" || echo "  ℹ mcp-server-globex not found, skipping"

# ── Step 3: AuthZ proxy deployment ───────────────────────────────────────────
echo ""
echo "▶ Step 3: Removing AuthZ proxy deployment..."
sudo kubectl delete -f k8s/mcp-server/mcp-server-deployment.yaml --ignore-not-found
echo "  ✓ AuthZ proxy deployment removed"

# ── Step 4: MCPToolInvocation CRD ────────────────────────────────────────────
echo ""
echo "▶ Step 4: Removing MCPToolInvocation CRD (and all CRs)..."
sudo kubectl delete mcptoolinvocations --all --all-namespaces --ignore-not-found
sudo kubectl delete -f k8s/crds/mcptoolinvocation-crd.yaml --ignore-not-found
echo "  ✓ MCPToolInvocation CRD and all custom resources removed"

# ── Step 5: Tenant namespaces + RBAC ─────────────────────────────────────────
echo ""
echo "▶ Step 5: Removing tenant namespaces and RBAC..."
sudo kubectl delete -f k8s/rbac/namespaces-and-rbac.yaml --ignore-not-found
echo "  ✓ tenant-acme, tenant-globex namespaces removed"
echo "  ✓ ServiceAccounts and RBAC removed"

# ── Step 6: Kyverno ──────────────────────────────────────────────────────────
echo ""
echo "▶ Step 6: Uninstalling Kyverno..."
sudo helm uninstall kyverno --namespace kyverno 2>/dev/null && echo "  ✓ Kyverno uninstalled" || echo "  ℹ Kyverno not found, skipping"
sudo kubectl delete namespace kyverno --ignore-not-found
echo "  ✓ Kyverno namespace removed"

# ── Step 7: kind cluster ──────────────────────────────────────────────────────
echo ""
echo "▶ Step 7: Deleting kind cluster '${CLUSTER_NAME}'..."
if sudo kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  sudo kind delete cluster --name "${CLUSTER_NAME}"
  echo "  ✓ Cluster '${CLUSTER_NAME}' deleted"
else
  echo "  ℹ Cluster '${CLUSTER_NAME}' not found, skipping"
fi

# ── Docker image cleanup ──────────────────────────────────────────────────────
echo ""
echo "▶ Cleaning up local Docker image..."
sudo docker rmi mcp-authz-proxy:demo 2>/dev/null && echo "  ✓ mcp-authz-proxy:demo removed" || echo "  ℹ Image not found, skipping"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   ✅ Teardown complete!                                  ║"
echo "║                                                          ║"
echo "║  All demo resources have been removed.                   ║"
echo "║  Re-run setup.sh to set up the stack again.         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""