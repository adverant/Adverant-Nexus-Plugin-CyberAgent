# Nexus-CyberAgent Testing Sandbox (Tier 2)
# Kali Linux-based security testing environment with 100+ tools

FROM kalilinux/kali-rolling:latest

LABEL maintainer="Adverant Brain Team"
LABEL description="Testing Sandbox for network security assessments and penetration testing"
LABEL tier="tier2"
LABEL version="1.0.0"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Update and install core system packages
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
    screen \
    net-tools \
    iputils-ping \
    dnsutils \
    netcat-openbsd \
    tcpdump \
    iptables \
    # Build tools
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    # Python ecosystem
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    # Go (for modern tools)
    golang-go \
    # Ruby (for Metasploit)
    ruby \
    ruby-dev \
    # Additional libraries
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Kali Linux security tools
RUN apt-get update && apt-get install -y \
    # Network reconnaissance
    nmap \
    masscan \
    rustscan \
    dnsenum \
    dnsrecon \
    fierce \
    sublist3r \
    amass \
    subfinder \
    # Vulnerability scanning
    nuclei \
    nikto \
    wapiti \
    # Web application testing
    zaproxy \
    burpsuite \
    wpscan \
    dirb \
    gobuster \
    dirbuster \
    ffuf \
    # Database testing
    sqlmap \
    # Password cracking
    hashcat \
    john \
    hydra \
    medusa \
    # Wireless
    aircrack-ng \
    wifite \
    reaver \
    # Exploitation frameworks
    metasploit-framework \
    # Traffic analysis
    wireshark \
    tshark \
    # SSL/TLS testing
    sslscan \
    sslyze \
    testssl.sh \
    # DNS tools
    dnsutils \
    # Additional tools
    whatweb \
    wafw00f \
    commix \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install additional Go-based tools
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/tomnomnom/gf@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/hakluke/hakrawler@latest

# Copy Go binaries to /usr/local/bin
RUN cp /root/go/bin/* /usr/local/bin/ 2>/dev/null || true

# Update Nuclei templates
RUN nuclei -update-templates

# Install Python-based security tools
RUN pip3 install --no-cache-dir \
    # Core dependencies
    requests \
    beautifulsoup4 \
    lxml \
    urllib3 \
    # Web frameworks
    fastapi==0.104.1 \
    uvicorn[standard]==0.24.0 \
    pydantic==2.4.2 \
    # Async support
    aiohttp \
    httpx \
    # Security libraries
    scapy \
    impacket \
    pycryptodome \
    cryptography \
    # Pentesting tools
    pwntools \
    ropper \
    # Utilities
    python-dotenv \
    colorama \
    tqdm \
    tabulate \
    # Cloud security
    boto3 \
    azure-cli \
    google-cloud-storage \
    # Parsing
    xmltodict \
    pyyaml \
    jsonschema

# Create wordlists directory and download SecLists
RUN mkdir -p /usr/share/wordlists && \
    cd /usr/share/wordlists && \
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git && \
    # Download rockyou.txt
    wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt || true

# Create application directories
RUN mkdir -p /app/src /app/tools /app/wordlists /app/results /app/logs

# Set up environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV WORDLIST_PATH=/usr/share/wordlists
ENV RESULTS_PATH=/app/results
ENV GOPATH=/root/go
ENV PATH="${PATH}:${GOPATH}/bin:/usr/local/bin"

# Copy application code
COPY src/ /app/src/
COPY tools/ /app/tools/
COPY requirements.txt /app/

# Install Python application dependencies
WORKDIR /app
RUN pip3 install --no-cache-dir -r requirements.txt

# Create non-root user for tool execution (security best practice)
RUN useradd -m -s /bin/bash -u 1000 cyberagent && \
    chown -R cyberagent:cyberagent /app && \
    # Grant necessary capabilities for privileged operations
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service=+eip /usr/bin/nmap || true && \
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service=+eip /usr/bin/masscan || true

# Expose API port
EXPOSE 9260

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:9260/health || exit 1

# Run API server
CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "9260", "--workers", "4"]
