FROM nicolaka/netshoot:latest

WORKDIR /app

RUN apk add gost sing-box

COPY ./network-probe ./
