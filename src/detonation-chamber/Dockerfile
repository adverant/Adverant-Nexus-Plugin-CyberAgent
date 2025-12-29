# Nexus-CyberAgent Detonation Chamber (Tier 3)
# Air-gapped malware analysis environment with Cuckoo Sandbox + KVM

FROM ubuntu:22.04

LABEL maintainer="Adverant Brain Team"
LABEL description="Detonation Chamber for air-gapped malware analysis and behavioral monitoring"
LABEL tier="tier3"
LABEL version="1.0.0"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Install system dependencies
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    # Core system utilities
    apt-transport-https \
    ca-certificates \
    curl \
    wget \
    git \
    vim \
    nano \
    tmux \
    net-tools \
    iputils-ping \
    dnsutils \
    tcpdump \
    iptables \
    bridge-utils \
    # Build tools
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    automake \
    autoconf \
    libtool \
    pkg-config \
    # Python ecosystem
    python3.10 \
    python3.10-dev \
    python3-pip \
    python3-venv \
    python3-setuptools \
    # Virtualization (KVM/QEMU)
    qemu-kvm \
    qemu-system-x86 \
    qemu-utils \
    libvirt-daemon-system \
    libvirt-clients \
    virtinst \
    virt-manager \
    bridge-utils \
    # Libraries
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libjpeg-dev \
    libpq-dev \
    # Forensics tools
    volatility3 \
    foremost \
    binwalk \
    exiftool \
    # Network analysis
    wireshark \
    tshark \
    zeek \
    suricata \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Python 3.10 as default
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1 && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3.10 1

# Install reverse engineering tools
RUN apt-get update && apt-get install -y \
    # Disassemblers and debuggers
    radare2 \
    gdb \
    ltrace \
    strace \
    # Binary analysis
    binutils \
    objdump \
    # Additional tools
    upx-ucl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Ghidra
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip \
    -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt/ && \
    rm /tmp/ghidra.zip && \
    ln -s /opt/ghidra_10.4_PUBLIC /opt/ghidra

# Install Java for Ghidra
RUN apt-get update && apt-get install -y openjdk-17-jdk && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install YARA
RUN apt-get update && apt-get install -y yara && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Python packages for malware analysis
RUN pip3 install --no-cache-dir \
    # Core dependencies
    requests \
    beautifulsoup4 \
    lxml \
    urllib3 \
    # Web framework
    fastapi==0.104.1 \
    uvicorn[standard]==0.24.0 \
    pydantic==2.4.2 \
    pydantic-settings==2.0.3 \
    # Async support
    aiohttp \
    httpx \
    # Malware analysis
    pefile \
    capstone \
    unicorn \
    keystone-engine \
    ropper \
    # Volatility 3
    volatility3 \
    # Yara Python
    yara-python \
    # Network analysis
    scapy \
    pyshark \
    dpkt \
    # Cryptography
    pycryptodome \
    cryptography \
    # Database
    asyncpg \
    redis \
    # Utilities
    python-dotenv \
    colorama \
    tqdm \
    tabulate \
    python-dateutil \
    # Logging
    python-json-logger \
    prometheus-client \
    # Testing
    pytest \
    pytest-asyncio

# Install Cuckoo Sandbox dependencies
RUN pip3 install --no-cache-dir \
    cuckoo \
    sqlalchemy \
    jinja2 \
    chardet \
    requests \
    python-magic \
    pydeep \
    androguard

# Install additional analysis tools via pip
RUN pip3 install --no-cache-dir \
    oletools \
    pdfid \
    peepdf \
    distorm3 \
    bottle \
    django \
    gunicorn

# Create application directories
RUN mkdir -p \
    /app/src \
    /app/tools \
    /app/malware \
    /app/results \
    /app/logs \
    /app/snapshots \
    /cuckoo \
    /vms

# Create Cuckoo working directory
RUN mkdir -p /root/.cuckoo && \
    cuckoo init || true

# Set up KVM permissions
RUN usermod -aG kvm root && \
    chmod 666 /dev/kvm || true

# Configure libvirt
RUN systemctl enable libvirtd || true

# Create network bridge for VMs
RUN cat > /etc/netplan/99-cuckoo-bridge.yaml <<EOF
network:
  version: 2
  renderer: networkd
  bridges:
    br0:
      dhcp4: no
      addresses:
        - 172.31.2.1/24
EOF

# Copy application code
COPY src/ /app/src/
COPY tools/ /app/tools/
COPY requirements.txt /app/
COPY cuckoo-config/ /root/.cuckoo/conf/

# Install additional Python dependencies
WORKDIR /app
RUN pip3 install --no-cache-dir -r requirements.txt

# Set up environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV MALWARE_PATH=/app/malware
ENV RESULTS_PATH=/app/results
ENV CUCKOO_PATH=/cuckoo
ENV GHIDRA_HOME=/opt/ghidra
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Expose API port (internal only - no external access)
EXPOSE 9270

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD curl -f http://localhost:9270/health || exit 1

# Startup script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "9270", "--workers", "2"]
