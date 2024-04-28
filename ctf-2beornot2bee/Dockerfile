FROM golang:alpine AS build

COPY backend /app
WORKDIR /app
ENV CGO_ENABLED=0
RUN go build -o /tmp/2beornot2bee -ldflags "-s -w" .

FROM scratch

COPY --from=build /tmp/2beornot2bee /2beornot2bee
COPY assets/bee_imgs /bee_imgs
COPY assets/bee_data.csv /bee_data.csv

CMD ["/2beornot2bee"]