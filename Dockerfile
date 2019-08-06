FROM alpine:3.10

RUN apk add --no-cache git bash ca-certificates && update-ca-certificates

ADD anchore /usr/local/bin

ADD bin/scanner-anchore /app/scanner-anchore

ENTRYPOINT ["/app/scanner-anchore"]
