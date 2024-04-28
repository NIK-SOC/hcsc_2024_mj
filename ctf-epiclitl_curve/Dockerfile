FROM golang:alpine AS build

COPY backend /app
WORKDIR /app
ENV CGO_ENABLED=0
RUN go build -o /tmp/ctf-epiclitl_curve -ldflags "-s -w" .

FROM scratch
COPY --from=build /tmp/ctf-epiclitl_curve /ctf-epiclitl_curve
CMD ["/ctf-epiclitl_curve"]