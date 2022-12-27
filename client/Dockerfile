FROM golang:1.19-alpine

WORKDIR /go/src/client

COPY . .

RUN go mod tidy

CMD ["go", "run", "."]
