# 🐧 Kali Security Tools - Offline Kurulum Rehberi

Bu rehber, internete erişimi olmayan (air-gapped) Red Hat/CentOS sunucularına güvenlik araçlarını nasıl kuracağınızı açıklar.

---

## 📦 İndirilecek Paketler

Aşağıdaki dosyaları internete erişimi olan bir bilgisayara indirin ve USB/DVD ile sunucuya aktarın.

### 1. Nmap - Ağ Tarayıcı

| Dosya | Link |
|-------|------|
| `nmap-7.94-1.x86_64.rpm` | <https://nmap.org/dist/nmap-7.94-1.x86_64.rpm> |
| `nmap-7.94.tar.bz2` (kaynak) | <https://nmap.org/dist/nmap-7.94.tar.bz2> |

```bash
# RPM kurulum
sudo rpm -ivh nmap-7.94-1.x86_64.rpm

# Kaynak kurulum
tar -xjf nmap-7.94.tar.bz2
cd nmap-7.94
./configure && make && sudo make install
```

### 2. SQLMap - SQL Injection Test

| Dosya | Link |
|-------|------|
| `sqlmap-1.8.zip` | <https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip> |

```bash
unzip sqlmap-1.8.zip -d /opt/security-tools/
# Kullanım:
python3 /opt/security-tools/sqlmap/sqlmap.py -u "http://target.com?id=1"
```

### 3. Nikto - Web Server Scanner

| Dosya | Link |
|-------|------|
| `nikto-master.zip` | <https://github.com/sullo/nikto/archive/refs/heads/master.zip> |

```bash
unzip nikto-master.zip -d /opt/security-tools/
# Kullanım:
perl /opt/security-tools/nikto/program/nikto.pl -h http://target.com
```

### 4. Hydra - Brute Force Tool

| Dosya | Link |
|-------|------|
| `thc-hydra-9.5.tar.gz` | <https://github.com/vanhauser-thc/thc-hydra/archive/refs/tags/v9.5.tar.gz> |

```bash
tar -xzf thc-hydra-9.5.tar.gz
cd thc-hydra-9.5
./configure && make && sudo make install
```

### 5. Gobuster - Directory Brute Force

| Dosya | Link |
|-------|------|
| `gobuster_3.6.0_Linux_x86_64.tar.gz` | <https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_3.6.0_Linux_x86_64.tar.gz> |

```bash
tar -xzf gobuster_3.6.0_Linux_x86_64.tar.gz
sudo mv gobuster /usr/local/bin/
```

### 6. Nuclei - Vulnerability Scanner

| Dosya | Link |
|-------|------|
| `nuclei_3.2.0_linux_amd64.zip` | <https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip> |
| `nuclei-templates.zip` | <https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip> |

```bash
unzip nuclei_3.2.0_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
# Templates
unzip nuclei-templates.zip -d ~/.local/nuclei-templates
```

### 7. Ffuf - Web Fuzzer

| Dosya | Link |
|-------|------|
| `ffuf_2.1.0_linux_amd64.tar.gz` | <https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz> |

```bash
tar -xzf ffuf_2.1.0_linux_amd64.tar.gz
sudo mv ffuf /usr/local/bin/
```

### 8. WhatWeb - Technology Fingerprinting

| Dosya | Link |
|-------|------|
| `WhatWeb-0.5.5.tar.gz` | <https://github.com/urbanadventurer/WhatWeb/archive/refs/tags/v0.5.5.tar.gz> |

```bash
tar -xzf WhatWeb-0.5.5.tar.gz
cd WhatWeb-0.5.5
sudo make install
```

### 9. WPScan - WordPress Scanner

| Dosya | Link |
|-------|------|
| `wpscan gem` | Ruby gem olarak kurulur |

```bash
# Önce Ruby ve gerekli paketler kurulmalı
sudo gem install wpscan --local wpscan-*.gem
```

### 10. SSLyze - SSL/TLS Analyzer

| Dosya | Link |
|-------|------|
| `sslyze` (Python wheel) | <https://pypi.org/project/sslyze/#files> |

```bash
pip3 install sslyze-*.whl --no-index --find-links .
```

### 11. Dirb - Web Content Scanner

| Dosya | Link |
|-------|------|
| `dirb222.tar.gz` | <https://sourceforge.net/projects/dirb/files/dirb/2.22/dirb222.tar.gz> |

```bash
tar -xzf dirb222.tar.gz
cd dirb222
./configure && make && sudo make install
```

---

## 📁 Wordlist Dosyaları

| Dosya | Link | Boyut |
|-------|------|-------|
| `rockyou.txt` | <https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt> | 139 MB |
| `common.txt` | <https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt> | 4.7 KB |
| `directory-list-2.3-medium.txt` | SecLists paketi | 2.3 MB |

---

## 🐳 Docker ile Kurulum

Docker kurulu ise tüm araçlar tek bir container'da:

```bash
# 1. Paketleri docker/packages/ dizinine kopyalayın
# 2. Docker image oluşturun
cd docker/kali-tools
docker build -t ibb-security-tools .

# 3. Container'ı çalıştırın
docker run -it --name security-scanner ibb-security-tools /bin/bash
```

---

## ⚙️ Red Hat/CentOS Dependencies

Araçları çalıştırmak için gereken bağımlılıklar:

```bash
# EPEL repo olmadan çalışacak paketler
sudo yum install -y \
    perl \
    perl-Net-SSLeay \
    python3 \
    python3-pip \
    ruby \
    ruby-devel \
    gcc \
    make \
    openssl-devel \
    libxml2-devel \
    libxslt-devel
```

---

## 🔗 Backend Entegrasyonu

Araçlar kurulduktan sonra, SiberAttack backend'i ile entegrasyon için:

1. `/etc/siberattack/tools.conf` dosyasını oluşturun
2. Araç yollarını belirtin
3. Backend servisini yeniden başlatın

```ini
# /etc/siberattack/tools.conf
[tools]
nmap=/usr/bin/nmap
sqlmap=/opt/security-tools/sqlmap/sqlmap.py
nikto=/opt/security-tools/nikto/program/nikto.pl
hydra=/usr/local/bin/hydra
gobuster=/usr/local/bin/gobuster
nuclei=/usr/local/bin/nuclei
ffuf=/usr/local/bin/ffuf
whatweb=/usr/local/bin/whatweb
wpscan=/usr/local/bin/wpscan
sslyze=/usr/local/bin/sslyze
dirb=/usr/local/bin/dirb
```
