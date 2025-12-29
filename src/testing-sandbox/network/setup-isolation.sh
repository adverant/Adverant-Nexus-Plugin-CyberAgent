#!/bin/bash
#
# Network Isolation Setup for Testing Sandbox
# Configures iptables rules to isolate sandbox from production
#

set -e

echo "Setting up network isolation for Testing Sandbox..."

# Configuration
SANDBOX_NETWORK="172.28.0.0/16"
API_GATEWAY_IP="172.28.0.10"
ALLOWED_PORTS="9260"  # Only allow API port

# Create custom chain for sandbox traffic
iptables -N SANDBOX_FILTER 2>/dev/null || iptables -F SANDBOX_FILTER

# Default policy: DROP all traffic from sandbox
iptables -A SANDBOX_FILTER -j DROP

# Allow traffic to API Gateway on port 9260
iptables -I SANDBOX_FILTER -d ${API_GATEWAY_IP} -p tcp --dport 9260 -j ACCEPT

# Allow DNS (for tool operations)
iptables -I SANDBOX_FILTER -p udp --dport 53 -j ACCEPT
iptables -I SANDBOX_FILTER -p tcp --dport 53 -j ACCEPT

# Allow established connections back
iptables -I SANDBOX_FILTER -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow ICMP (ping) for testing
iptables -I SANDBOX_FILTER -p icmp -j ACCEPT

# Apply sandbox filter to traffic from sandbox network
iptables -A FORWARD -s ${SANDBOX_NETWORK} -j SANDBOX_FILTER

# Allow traffic TO sandbox (responses)
iptables -A FORWARD -d ${SANDBOX_NETWORK} -m state --state ESTABLISHED,RELATED -j ACCEPT

# Log dropped packets (for debugging)
iptables -A SANDBOX_FILTER -j LOG --log-prefix "SANDBOX_DROP: " --log-level 4

echo "Network isolation configured successfully"
echo "Sandbox network: ${SANDBOX_NETWORK}"
echo "API Gateway: ${API_GATEWAY_IP}:${ALLOWED_PORTS}"
echo ""
echo "Active iptables rules:"
iptables -L SANDBOX_FILTER -n -v
