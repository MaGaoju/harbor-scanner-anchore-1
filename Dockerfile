FROM alpine:3.20

RUN apk add --no-cache git bash ca-certificates && update-ca-certificates

ADD bin/scanner-anchore /app/scanner-anchore

ENTRYPOINT ["/app/scanner-anchore"]