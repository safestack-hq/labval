FROM golang:1.17.10-alpine AS builder
MAINTAINER Christian Frichot <christian@safestack.io>

RUN apk update
RUN apk upgrade
RUN apk add --update git make
WORKDIR /src
COPY . .
RUN go build -o labs-validator ./cmd/labs-validator

FROM alpine:latest AS labs-validator
WORKDIR /app
RUN apk --no-cache add ca-certificates
COPY --from=builder /src/labs-validator /bin/labs-validator
ENTRYPOINT ["/bin/labs-validator"]
