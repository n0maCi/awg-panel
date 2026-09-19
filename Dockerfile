# syntax=docker/dockerfile:1.7

FROM node:24-alpine AS application-build
WORKDIR /app
RUN npm install --global pnpm@11.19.0
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json tsconfig.server.json vite.config.ts vitest.config.ts index.html ./
COPY src ./src
RUN pnpm run build && pnpm prune --prod

FROM golang:1.25-alpine AS awg-go-build
ARG AWG_GO_TAG=v3.1.20260813
RUN apk add --no-cache git make build-base
RUN git clone --depth 1 --branch "${AWG_GO_TAG}" https://github.com/amnezia-vpn/amneziawg-go.git /src/amneziawg-go
WORKDIR /src/amneziawg-go
RUN make

FROM alpine:3.22 AS awg-tools-build
ARG AWG_TOOLS_TAG=v3.1.20260812
RUN apk add --no-cache git make build-base linux-headers
RUN git clone --depth 1 --branch "${AWG_TOOLS_TAG}" https://github.com/amnezia-vpn/amneziawg-tools.git /src/amneziawg-tools
WORKDIR /src/amneziawg-tools/src
RUN make

FROM node:24-alpine
LABEL org.opencontainers.image.title="AWG Panel"
LABEL org.opencontainers.image.description="Minimal AmneziaWG 1.5, 2.0 and 3.1 web panel"
WORKDIR /app

RUN apk add --no-cache bash dumb-init iproute2 iptables
COPY --from=awg-go-build /src/amneziawg-go/amneziawg-go /usr/bin/amneziawg-go
COPY --from=awg-tools-build /src/amneziawg-tools/src/wg /usr/bin/awg
COPY --from=awg-tools-build /src/amneziawg-tools/src/wg-quick/linux.bash /usr/bin/awg-quick
RUN chmod 0755 /usr/bin/amneziawg-go /usr/bin/awg /usr/bin/awg-quick \
    && ln -s /usr/bin/awg /usr/bin/wg \
    && ln -s /usr/bin/awg-quick /usr/bin/wg-quick \
    && ln -s /usr/bin/amneziawg-go /usr/bin/wireguard-go

COPY --from=application-build /app/dist ./dist
COPY --from=application-build /app/node_modules ./node_modules
COPY --from=application-build /app/package.json ./package.json
COPY scripts ./scripts

ENV NODE_ENV=production DATA_DIR=/data UI_PORT=51821
EXPOSE 51821/tcp 51820/udp
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:${UI_PORT}/api/health >/dev/null || exit 1
CMD ["/usr/bin/dumb-init", "--", "node", "dist/server/server/index.js"]
