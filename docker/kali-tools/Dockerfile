# Kali Security Tools Docker Image
# Offline/Air-gapped Server için hazırlandı
# Red Hat/CentOS tabanlı sunucularda çalışır

FROM debian:bullseye-slim

LABEL maintainer="IBB Security Team"
LABEL description="Kali Linux Security Tools for Offline Penetration Testing"

# Temel paketleri kur
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    ruby \
    ruby-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Security Tools Directory
WORKDIR /opt/security-tools

# ===========================================
# OFFLINE KURULUM İÇİN PAKETLER
# Aşağıdaki dosyaları /opt/packages/ dizinine kopyalayın
# ===========================================

# 1. NMAP
# Offline: nmap-7.94-1.x86_64.rpm veya nmap-7.94.tar.bz2
RUN apt-get update && apt-get install -y nmap || echo "Offline: Copy nmap package manually"

# 2. NIKTO - Perl tabanlı
RUN git clone https://github.com/sullo/nikto.git /opt/security-tools/nikto || echo "Offline: Extract nikto-2.5.0.tar.gz to /opt/security-tools/nikto"

# 3. SQLMAP - Python tabanlı
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/security-tools/sqlmap || echo "Offline: Extract sqlmap to /opt/security-tools/sqlmap"

# 4. HYDRA
RUN apt-get update && apt-get install -y hydra || echo "Offline: Build hydra from source"

# 5. DIRB
RUN apt-get update && apt-get install -y dirb || echo "Offline: Build dirb from source"

# 6. GOBUSTER (Go binary - pre-compiled)
# Offline: gobuster-linux-amd64.tar.gz
RUN mkdir -p /opt/security-tools/gobuster
COPY packages/gobuster* /opt/security-tools/gobuster/ 2>/dev/null || echo "Offline: Copy gobuster binary"

# 7. NUCLEI (Go binary - pre-compiled)
# Offline: nuclei_linux_amd64.zip
RUN mkdir -p /opt/security-tools/nuclei
COPY packages/nuclei* /opt/security-tools/nuclei/ 2>/dev/null || echo "Offline: Copy nuclei binary"

# 8. FFUF (Go binary - pre-compiled)
# Offline: ffuf_linux_amd64.tar.gz
RUN mkdir -p /opt/security-tools/ffuf
COPY packages/ffuf* /opt/security-tools/ffuf/ 2>/dev/null || echo "Offline: Copy ffuf binary"

# 9. WHATWEB - Ruby tabanlı
RUN git clone https://github.com/urbanadventurer/WhatWeb.git /opt/security-tools/whatweb || echo "Offline: Extract whatweb to /opt/security-tools/whatweb"

# 10. WPSCAN - Ruby gem
RUN gem install wpscan || echo "Offline: Install wpscan gem from cache"

# 11. SSLYZE - Python
RUN pip3 install sslyze || echo "Offline: pip3 install sslyze from wheel"

# Wordlists dizini
RUN mkdir -p /opt/wordlists
# Offline: Aşağıdaki wordlist'leri kopyalayın
# - rockyou.txt
# - common.txt
# - directory-list-2.3-medium.txt

# PATH'e araçları ekle
ENV PATH="/opt/security-tools/gobuster:/opt/security-tools/nuclei:/opt/security-tools/ffuf:/opt/security-tools/nikto/program:/opt/security-tools/sqlmap:${PATH}"

# Scanner script'i
COPY scripts/scanner.sh /opt/security-tools/scanner.sh
RUN chmod +x /opt/security-tools/scanner.sh 2>/dev/null || true

# Health check
HEALTHCHECK --interval=30s --timeout=10s CMD nmap --version || exit 1

# Default command
CMD ["/bin/bash"]
