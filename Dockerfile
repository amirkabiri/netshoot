FROM ubuntu:latest

USER root
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y kcptun

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    vim \
    nano \
    ca-certificates \
    gnupg \
    procps \
    git \
    iputils-ping \
    net-tools \
    iproute2 \
    netcat-openbsd \
    telnet \
    nmap \
    iperf3 \
    mtr-tiny \
    traceroute \
    tcpdump \
    dnsutils \
    socat \
    openssh-client \
    openssh-server \
    nginx \
    python3 \
    python3-pip \
    python3-venv

RUN mkdir /var/run/sshd && \
    echo 'root:root' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

RUN GOST_VERSION=$(curl -s https://api.github.com/repos/go-gost/gost/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/v//') && \
    wget https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_linux_amd64.tar.gz && \
    tar -zxvf gost_${GOST_VERSION}_linux_amd64.tar.gz && \
    mv gost /usr/local/bin/gost && \
    chmod +x /usr/local/bin/gost && \
    rm gost_${GOST_VERSION}_linux_amd64.tar.gz

# Replace your existing sing-box RUN command with this:
RUN ARCH=$(dpkg --print-architecture) && \
    SB_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/v//') && \
    wget https://github.com/SagerNet/sing-box/releases/download/v${SB_VERSION}/sing-box-${SB_VERSION}-linux-${ARCH}.tar.gz && \
    tar -zxvf sing-box-${SB_VERSION}-linux-${ARCH}.tar.gz && \
    # The tar creates a folder, we find the binary inside and move it
    mv sing-box-*/sing-box /usr/local/bin/sing-box && \
    chmod +x /usr/local/bin/sing-box && \
    rm -rf sing-box-* \

WORKDIR /root

RUN sing-box version && \
    gost -V && \
    python3 --version && \
    kcptun-server --version && \
    nginx -v

COPY ./network-probe ./network-probe

CMD ["/bin/bash"]
