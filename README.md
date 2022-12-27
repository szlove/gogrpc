# gogrpc
gRPC example with golang

# Docker containers
- database
	- postgres:14-alpine
	- port: 5432
- backend
	- golang:1.19-alpine
	- port: 8000
- client
	- golang:1.19-alpine
	- port: 4000

# gRPC example
client request -> backend -> database -> backend response -> client

# gRPC API
User service

- SignUp
- GetUserByID
- SignIn
- ChangePassword
- DeleteUser

# Makefile command
- up: docker compose up
- down: docker compose down
- psql: exec psql
