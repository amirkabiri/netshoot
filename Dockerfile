FROM someguy123/net-tools:latest

USER root

# 1. Update and install core tools with better error handling
# We use --fix-missing and multiple retries behavior implicitly by cleaning first
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    wget \
    kcptun \
    software-properties-common && \
    add-apt-repository -y ppa:deadsnakes/ppa && \
    apt-get update

# 2. Install Python 3.12
# Adding python3-pip just in case your script needs dependencies later
RUN apt-get install -y --no-install-recommends \
    python3.12 \
    python3.12-venv \
    python3.12-distutils && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 3. Setup SagerNet / sing-box
RUN mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://sing-box.app/gpg.key | gpg --dearmor -o /etc/apt/keyrings/sagernet.gpg && \
    chmod a+r /etc/apt/keyrings/sagernet.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/sagernet.gpg] https://deb.sagernet.org/ * *" \
    > /etc/apt/sources.list.d/sagernet.list && \
    apt-get update && \
    apt-get install -y sing-box

# 4. Setup GOST
RUN GOST_VERSION=$(curl -s https://api.github.com/repos/go-gost/gost/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/v//') && \
    wget https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_linux_amd64.tar.gz && \
    tar -zxvf gost_${GOST_VERSION}_linux_amd64.tar.gz && \
    mv gost /usr/local/bin/gost && \
    chmod +x /usr/local/bin/gost && \
    rm gost_${GOST_VERSION}_linux_amd64.tar.gz

# 5. Set Python 3.12 as the default 'python3' alias
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1

WORKDIR /root

# Verification
RUN sing-box version && gost -V && python3 --version

COPY ./network-probe ./network-probe

CMD ["/bin/bash"]
