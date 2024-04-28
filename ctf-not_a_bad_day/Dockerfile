FROM docker.io/golang:alpine AS build

COPY backend /src

RUN cd /src && go build -o /tmp/not_a_bad_day -ldflags "-s -w"

FROM scratch

COPY --from=build /tmp/not_a_bad_day /not_a_bad_day
COPY assets/fs.img /fs.img

CMD ["/not_a_bad_day"]