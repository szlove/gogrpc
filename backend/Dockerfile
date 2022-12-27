FROM golang:1.19-alpine

WORKDIR /go/src/backend

COPY . .

RUN go mod tidy

CMD ["go", "run", "."]
