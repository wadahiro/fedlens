FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go run github.com/a-h/templ/cmd/templ@v0.3.977 generate
RUN CGO_ENABLED=0 go build -o fedlens .

FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/fedlens /fedlens
ENTRYPOINT ["/fedlens"]
