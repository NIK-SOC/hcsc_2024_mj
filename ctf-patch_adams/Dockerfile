FROM golang:alpine AS build

COPY backend /app
WORKDIR /app
ENV CGO_ENABLED=0
RUN go build -o /tmp/patch_adams -ldflags "-s -w" .

FROM alpine:latest as intermediate

RUN adduser -D -s /bin/false challenger && \
    chown -R root:root /home/challenger && \
    chmod -R 555 /home/challenger && \
    chmod 555 /var/tmp && \
    chmod 555 /dev && \
    chmod 555 /run && \
    apk add --no-cache radare2

COPY --from=build /tmp/patch_adams /home/challenger/patch_adams
COPY out/adams /home/challenger/adams
COPY assets/flag.txt /secret/flag.txt

# ugly, but less layers
FROM scratch

COPY --from=intermediate / /
USER challenger
WORKDIR /home/challenger

CMD ["./patch_adams"]