FROM golang:1.24.2 AS builder

WORKDIR /src

COPY . .

RUN go get -v . \
    && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o csp-report-handler .

FROM alpine:3.21.3

WORKDIR /opt

COPY --from=builder /src/csp-report-handler .

CMD ["./csp-report-handler"]
