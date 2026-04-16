FROM someguy123/net-tools:latest

WORKDIR /app

RUN apt update
RUN apt install gost sing-box kcptun

COPY ./network-probe ./network-probe
