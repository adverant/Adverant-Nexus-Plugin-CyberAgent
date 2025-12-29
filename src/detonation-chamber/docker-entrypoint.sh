#!/bin/bash
#
# Detonation Chamber Entrypoint Script
# Initializes KVM, libvirt, and starts analysis services
#

set -e

echo "========================================="
echo "Nexus-CyberAgent Detonation Chamber"
echo "Air-gapped Malware Analysis Environment"
echo "========================================="

# Check if running with required privileges
if [ ! -c /dev/kvm ]; then
    echo "WARNING: /dev/kvm not available. Nested virtualization may not work."
    echo "Make sure container is started with --device /dev/kvm"
fi

# Start libvirtd if available
if command -v libvirtd &> /dev/null; then
    echo "Starting libvirt daemon..."
    libvirtd -d || true
    sleep 2
fi

# Configure network bridge for VMs
echo "Configuring network bridge..."
if command -v netplan &> /dev/null; then
    netplan apply 2>/dev/null || true
fi

# Create required directories
echo "Creating required directories..."
mkdir -p /app/malware
mkdir -p /app/results
mkdir -p /app/logs
mkdir -p /app/snapshots
mkdir -p /vms

# Set permissions
chmod 755 /app/malware
chmod 755 /app/results

# Initialize Cuckoo if not already done
if [ ! -f /root/.cuckoo/.cwd ]; then
    echo "Initializing Cuckoo Sandbox..."
    cuckoo init || true
fi

# Start Cuckoo services in background (if configured)
if [ -f /root/.cuckoo/conf/cuckoo.conf ]; then
    echo "Starting Cuckoo services..."
    (cd /root/.cuckoo && cuckoo -d 2>&1 | tee /app/logs/cuckoo.log) &
    sleep 5
fi

# Health check
echo "Running health checks..."
python3 -c "import volatility3; print('✓ Volatility3 available')" || echo "✗ Volatility3 not available"
python3 -c "import yara; print('✓ YARA available')" || echo "✗ YARA not available"
python3 -c "import pefile; print('✓ pefile available')" || echo "✗ pefile not available"

echo "========================================="
echo "Detonation Chamber initialized"
echo "API starting on port 9270..."
echo "========================================="

# Execute the command passed to docker run
exec "$@"
