FROM nicolaka/netshoot:latest

WORKDIR /app

RUN apk add gost sing-box kcptun

COPY ./network-probe ./
