# Created with Strapit
FROM    golang:1.18-buster as builder
WORKDIR /app
COPY    . ./
RUN     go build -o service

FROM    debian:buster-slim
COPY    --from=builder /app/service /app/service
CMD     ["/app/service"]
