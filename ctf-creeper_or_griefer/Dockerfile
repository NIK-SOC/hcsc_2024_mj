FROM golang:alpine AS builder

RUN apk add --no-cache git && \
    git clone --depth 1 --single-branch --branch main https://github.com/Etrayed/signum /app && \
    cd /app && \
    go build -ldflags "-s -w" -o /tmp/signum

FROM scratch

ENV SIGNUM_STATUS='{"version":{"name":"1.20.4","protocol":765},"players":{"max":2024,"online":420,"sample":[{"name":"HCSC24{y0u_l34ve","id":"889841b3-88f0-4911-b12b-f0738cfae6e2"},{"name":"_tr4ces_everywhe","id":"14347505-e5f4-433d-b7f5-f84150041272"},{"name":"re}","id":"318331c8-a0fb-4fe9-8d77-21869be91315"}]},"description":{"text":"Epic gaming happens here"},"enforcesSecureChat":true,"previewsChat":true}'
ENV SIGNUM_KICK_MESSAGE='{"text":"You are not white-listed on this server!"}'

COPY --from=builder /tmp/signum /signum

CMD ["/signum"]