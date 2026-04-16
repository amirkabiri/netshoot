FROM someguy123/net-tools:latest

USER root

RUN apt update && apt install -y \
    curl \
    ca-certificates \
    gpg \
    wget \
    kcptun

RUN mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://sing-box.app/gpg.key | gpg --dearmor -o /etc/apt/keyrings/sagernet.gpg && \
    chmod a+r /etc/apt/keyrings/sagernet.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/sagernet.gpg] https://deb.sagernet.org/ * *" \
    > /etc/apt/sources.list.d/sagernet.list && \
    apt-get update && \
    apt-get install -y sing-box

RUN GOST_VERSION=$(curl -s https://api.github.com/repos/go-gost/gost/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/v//') && \
    wget https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_linux_amd64.tar.gz && \
    tar -zxvf gost_${GOST_VERSION}_linux_amd64.tar.gz && \
    mv gost /usr/local/bin/gost && \
    chmod +x /usr/local/bin/gost && \
    rm gost_${GOST_VERSION}_linux_amd64.tar.gz

WORKDIR /root

RUN sing-box version && gost -V

COPY ./network-probe ./network-probe

CMD ["/bin/bash"]
