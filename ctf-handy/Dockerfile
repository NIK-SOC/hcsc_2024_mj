FROM golang:alpine AS build

COPY backend /app
WORKDIR /app
ENV CGO_ENABLED=0
RUN go build -o /tmp/ctf-handy -ldflags "-s -w" .

FROM scratch
COPY --from=build /tmp/ctf-handy /ctf-handy
CMD ["/ctf-handy"]