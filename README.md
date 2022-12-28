# gogrpc
gRPC example with golang

## Docker containers
- database
	- postgres:14-alpine
	- port: 5432
- backend
	- golang:1.19-alpine
	- port: 8000
- client
	- golang:1.19-alpine
	- port: 4000

## gRPC example
client request -> backend -> database -> backend response -> client

## gRPC API
User service

- SignUp
- GetUserByID
- SignIn
- ChangePassword
- DeleteUser

## Makefile command
- up: docker compose up
- down: docker compose down
- psql: exec psql



## docker-compose.yml
```yml
version: "3.9"

services:
  database:
    container_name: database
    build:
      context: ./database
    environment:
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - TZ=Asia/Seoul
    ports:
      - "5432:5432"
    volumes:
      - ./database:/docker-entrypoint-initdb.d
    restart: always
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER}"]
      interval: 0.1s
      timeout: 5s
      retries: 10

  backend:
    container_name: backend
    build:
      context: ./backend
    environment:
      - PORT=8000
      - DB_HOST=database
      - DB_PORT=5432
      - DB_USER=${DB_USER}
      - DB_PASSWORD=${DB_PASSWORD}
      - DB_NAME=${DB_NAME}
      - API_KEY=${API_KEY}
      - TOKEN_SECRET=${TOKEN_SECRET}
      - TZ=Asia/Seoul
    ports:
      - "8000:8000"
    volumes:
      - ./backend:/go/src/backend
    # restart: always
    depends_on:
      database:
        condition: service_healthy

  client:
    container_name: client
    build:
      context: ./client
    environment:
      - PORT=4000
      - BACKEND_HOST=backend:8000
      - API_KEY=${API_KEY}
      - TZ=Asia/Seoul
    ports:
      - "4000:4000"
    volumes:
      - ./client:/go/src/client
    # restart: always
    depends_on:
      - backend
```

## Makefile
```Makefile
.PHONY:
	up down psql clear

up:
	@read -p "Enter DB_USER: " db_user \
	&& read -p "Enter DB_PASSWORD: " db_password \
	&& read -p "Enter DB_NAME: " db_name \
	&& read -p "Enter API_KEY: " API_KEY \
	&& read -p "Enter TOKEN_SECRET: " token_secret \
	&& DB_USER=$$db_user DB_PASSWORD=$$db_password DB_NAME=$$db_name API_KEY=$$api_key TOKEN_SECRET=$$token_secret docker compose up -d

down:
	docker compose down \
	&& docker system prune -af \
	&& docker volume prune -f

psql:
	@read -p "Enter DB_USER: " db_user \
	&& docker compose exec -it database psql -U $$db_user
```
## databse/Dockerfile
```Dockerfile
FROM postgres:14-alpine

WORKDIR docker-entrypoint-initdb.d

COPY . docker-entrypoint-initdb.d
```

## database/table.sql
```sql
CREATE TABLE IF NOT EXISTS users (
	id         VARCHAR(20)  NOT NULL PRIMARY KEY,
	password   VARCHAR(60)  NOT NULL, -- bcrypt hash
	name       VARCHAR(20)  NOT NULL,
	email      VARCHAR(100) NOT NULL,
	created_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

## backend/Dockerfile
```Dockerfile
FROM golang:1.19-alpine

WORKDIR /go/src/backend

COPY . .

RUN go mod tidy

CMD ["go", "run", "."]
```

## backend/Makefile
```Makefile
.PHONY:
	protoc clear

protoc:
	protoc --proto_path=proto \
	--go_out=pb --go_opt=paths=source_relative \
	--go-grpc_out=pb --go-grpc_opt=paths=source_relative \
	proto/*.proto

clear:
	rm pb/*
```

## backend/main.go
```go
package main

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/szlove/gogrpc/backend/db"
	"github.com/szlove/gogrpc/backend/server"
)

func init() {
	loc, err := time.LoadLocation(os.Getenv("TZ"))
	if err != nil {
		panic(err)
	}
	time.Local = loc
}

func main() {
	if err := db.Connection(&db.ConnectionParams{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
		DBName:   os.Getenv("DB_NAME"),
		SSLMode:  "disable",
	}); err != nil {
		panic(err)
	}
	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		panic(err)
	}
	log.Fatal(server.Run(uint32(port)))
}
```

## backend/db/db.go
```go
package db

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

var conn *sql.DB

type ConnectionParams struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

func dataSourceName(p *ConnectionParams) string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		p.Host, p.Port, p.User, p.Password, p.DBName, p.SSLMode)
}

func Connection(arg *ConnectionParams) error {
	db, err := sql.Open("postgres", dataSourceName(arg))
	if err != nil {
		return err
	}
	if err := db.Ping(); err != nil {
		return err
	}
	conn = db
	return nil
}

type Transaction struct {
	Tx  *sql.Tx
	Ctx context.Context
}

func NewTransaction() (*Transaction, error) {
	ctx := context.Background()
	tx, err := conn.BeginTx(ctx, nil)
	return &Transaction{tx, ctx}, err
}

func (t *Transaction) Rollback() error { return t.Tx.Rollback() }
func (t *Transaction) Commit() error   { return t.Tx.Commit() }
```

## backend/db/user.go
```go
package db

import (
	"database/sql"
	"errors"
	"time"
)

const (
	ERROR_USER_NOT_FOUND string = "회원 정보가 존재하지 않습니다"
)

type User struct {
	ID        string
	Password  string
	Name      string
	Email     string
	CreatedAt time.Time
}

const getUserByID = `
SELECT
	id, password, name, email, created_at
FROM
	users
WHERE
	id = $1;`

func GetUserByID(tx *Transaction, userID string) (u *User, has bool, err error) {
	u = &User{}
	err = tx.Tx.QueryRowContext(tx.Ctx, getUserByID, userID).Scan(&u.ID, &u.Password, &u.Name, &u.Email, &u.CreatedAt)
	switch err {
	case sql.ErrNoRows:
		return nil, false, nil
	case nil:
		return u, true, nil
	default:
		return nil, false, err
	}
}

const createUser = `
INSERT INTO users (
	id, password, name, email
) VALUES (
    $1, $2,       $3,   $4
);`

type CreateUserParams struct {
	ID       string
	Password string
	Name     string
	Email    string
}

func CreateUser(tx *Transaction, arg *CreateUserParams) error {
	r, err := tx.Tx.ExecContext(tx.Ctx, createUser, arg.ID, arg.Password, arg.Name, arg.Email)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("ERROR: Databse: 회원이 생성되지 않았습니다")
	}
	return nil
}

const changeUserPassword = `
UPDATE
	users
SET
	password = $2
WHERE
	id = $1;`

func (u *User) ChangePassword(tx *Transaction, newPasswordHash string) error {
	r, err := tx.Tx.ExecContext(tx.Ctx, changeUserPassword, u.ID, newPasswordHash)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("ERROR: Database: 비밀번호가 변경되지 않았습니다")
	}
	return nil
}

const deleteUser = `
DELETE FROM
	users
WHERE
	id = $1;`

func (u *User) Delete(tx *Transaction) error {
	r, err := tx.Tx.ExecContext(tx.Ctx, deleteUser, u.ID)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("ERROR: Database: 회원이 삭제되지 않았습니다")
	}
	return nil
}
```

## backend/proto/user.proto
```proto
syntax = "proto3";

package pb;

option go_package = "github.com/szlove/gogrpc/backend/pb";

import "google/protobuf/timestamp.proto";

message SignUpRequest {
	string api_key  = 1;
	string user_id  = 2;
	string password = 3;
	string name     = 4;
	string email    = 5;
}

message SignUpResponse {
	string message = 1;
	string user_id = 2;
}

message GetUserByIdRequest {
	string api_key = 1;
	string user_id = 2;
}

message GetUserByIdResponse {
	string                    id         = 1;
	string                    name       = 2;
	string                    email      = 3;
	google.protobuf.Timestamp created_at = 4;
}

message SignInRequest {
	string api_key  = 1;
	string user_id  = 2;
	string password = 3;
}

message SignInResponse {
	string token = 2;
}

message ChangePasswordRequest {
	string api_key          = 1;
	string token            = 2;
	string current_password = 3;
	string new_password     = 4;
}

message ChangePasswordResponse {
	string message = 1;
}

message DeleteUserRequest {
	string api_key  = 1;
	string token    = 2;
	string password = 3;
}

message DeleteUserResponse {
	string message = 1;
}

service User {
	rpc SignUp(SignUpRequest) returns (SignUpResponse) {}
	rpc GetUserById(GetUserByIdRequest) returns (GetUserByIdResponse) {}
	rpc SignIn(SignInRequest) returns (SignInResponse) {}
	rpc ChangePassword(ChangePasswordRequest) returns (ChangePasswordResponse) {}
	rpc Delete(DeleteUserRequest) returns (DeleteUserResponse) {}
}
```

## backend/server/server.go
```go
package server

import (
	"fmt"
	"log"
	"net"

	"github.com/szlove/gogrpc/backend/pb"
	"google.golang.org/grpc"
)

const (
	ERROR_INVALID_APIKEY string = "API Key가 유효하지 않습니다"
)

func registers(s *grpc.Server) {
	pb.RegisterUserServer(s, &UserServer{})
}

func Run(port uint32) error {
	portString := fmt.Sprintf(":%d", port)
	lis, err := net.Listen("tcp", portString)
	if err != nil {
		return err
	}
	grpcServer := grpc.NewServer()
	registers(grpcServer)
	log.Printf("Server listening at %s\n", portString)
	return grpcServer.Serve(lis)
}
```

## backend/server/user.go
```go
package server

import (
	"context"
	"errors"
	"os"

	"github.com/golang-jwt/jwt"
	"github.com/szlove/gogrpc/backend/db"
	"github.com/szlove/gogrpc/backend/pb"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type UserServer struct {
	pb.UnimplementedUserServer
}

func (*UserServer) SignUp(ctx context.Context, req *pb.SignUpRequest) (*pb.SignUpResponse, error) {
	if req.GetApiKey() != os.Getenv("API_KEY") {
		return nil, errors.New(ERROR_INVALID_APIKEY)
	}
	tx, err := db.NewTransaction()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	_, has, err := db.GetUserByID(tx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if has {
		return nil, errors.New("이미 사용중인 아이디 입니다")
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	if err := db.CreateUser(tx, &db.CreateUserParams{
		ID:       req.GetUserId(),
		Password: string(passwordHash),
		Name:     req.GetName(),
		Email:    req.GetEmail(),
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	res := &pb.SignUpResponse{Message: "ok", UserId: req.GetUserId()}
	return res, nil
}

func (*UserServer) GetUserById(ctx context.Context, req *pb.GetUserByIdRequest) (*pb.GetUserByIdResponse, error) {
	if req.GetApiKey() != os.Getenv("API_KEY") {
		return nil, errors.New(ERROR_INVALID_APIKEY)
	}
	tx, err := db.NewTransaction()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	user, has, err := db.GetUserByID(tx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, errors.New(db.ERROR_USER_NOT_FOUND)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	res := &pb.GetUserByIdResponse{
		Id:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		CreatedAt: timestamppb.New(user.CreatedAt),
	}
	return res, nil
}

type UserTokenClaims struct {
	UserID string
	jwt.StandardClaims
}

func (*UserServer) SignIn(ctx context.Context, req *pb.SignInRequest) (*pb.SignInResponse, error) {
	if req.GetApiKey() != os.Getenv("API_KEY") {
		return nil, errors.New(ERROR_INVALID_APIKEY)
	}
	tx, err := db.NewTransaction()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	user, has, err := db.GetUserByID(tx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, errors.New(db.ERROR_USER_NOT_FOUND)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.GetPassword())); err != nil {
		return nil, errors.New("비밀번호가 일치하지 않습니다")
	}
	claims := UserTokenClaims{UserID: user.ID}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("TOKEN_SECRET")))
	if err != nil {
		return nil, err
	}
	return &pb.SignInResponse{Token: tokenString}, nil
}

func parseUserClaims(tokenString string) (*UserTokenClaims, error) {
	claims := &UserTokenClaims{}
	KeyFunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Unexpected Signing Method")
		}
		return []byte(os.Getenv("TOKEN_SECRET")), nil
	}
	token, err := jwt.ParseWithClaims(tokenString, claims, KeyFunc)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("토큰 검증에 실패 했습니다")
	}
	return claims, nil
}

func (*UserServer) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	if req.GetApiKey() != os.Getenv("API_KEY") {
		return nil, errors.New(ERROR_INVALID_APIKEY)
	}
	tx, err := db.NewTransaction()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	claims, err := parseUserClaims(req.GetToken())
	if err != nil {
		return nil, err
	}
	user, has, err := db.GetUserByID(tx, claims.UserID)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, errors.New(db.ERROR_USER_NOT_FOUND)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.GetCurrentPassword())); err != nil {
		return nil, errors.New("현재 비밀번호가 일치하지 않습니다")
	}
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(req.GetNewPassword()), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	if err := user.ChangePassword(tx, string(newPasswordHash)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &pb.ChangePasswordResponse{Message: "ok"}, nil
}

func (*UserServer) Delete(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	if req.GetApiKey() != os.Getenv("API_KEY") {
		return nil, errors.New(ERROR_INVALID_APIKEY)
	}
	claims, err := parseUserClaims(req.GetToken())
	if err != nil {
		return nil, err
	}
	tx, err := db.NewTransaction()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	user, has, err := db.GetUserByID(tx, claims.UserID)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, errors.New(db.ERROR_USER_NOT_FOUND)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.GetPassword())); err != nil {
		return nil, errors.New("비밀번호가 일치하지 않습니다")
	}
	if err := user.Delete(tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &pb.DeleteUserResponse{Message: "ok"}, nil
}
```

## client/Dockerfile
```Dockerfile
FROM golang:1.19-alpine

WORKDIR /go/src/client

COPY . .

RUN go mod tidy

CMD ["go", "run", "."]
```

## client/Makefile
```Makefile
.PHONY:
	protoc clear

protoc:
	protoc --proto_path=proto \
	--go_out=pb --go_opt=paths=source_relative \
	--go-grpc_out=pb --go-grpc_opt=paths=source_relative \
	proto/*.proto

clear:
	rm pb/*.pb.go
```

## client/main.go
```go
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/szlove/gogrpc/client/pb"
)

func init() {
	loc, err := time.LoadLocation(os.Getenv("TZ"))
	if err != nil {
		panic(err)
	}
	time.Local = loc
}

var (
	TEST_USER_ID       string = "example"
	TEST_USER_PASSWORD string = "example1234"
	TEST_USER_NAME     string = "kim exam ple"
	TEST_USER_EMAIL    string = "foo@example.com"
)

func main() {
	// gRPC client
	client := pb.NewUserClient(pb.Conn)
	// SignUp
	signUpResponse, err := client.SignUp(context.Background(), &pb.SignUpRequest{
		ApiKey:   os.Getenv("API_KEY"),
		UserId:   TEST_USER_ID,
		Password: TEST_USER_PASSWORD,
		Name:     TEST_USER_NAME,
		Email:    TEST_USER_EMAIL,
	})
	if err != nil {
		panic(err)
	}
	log.Println("SignUpResponse:")
	log.Printf("%+v\n\n", signUpResponse)
	// GetUserByID
	getUserByIdResponse, err := client.GetUserById(context.Background(), &pb.GetUserByIdRequest{
		ApiKey: os.Getenv("API_KEY"),
		UserId: TEST_USER_ID,
	})
	if err != nil {
		panic(err)
	}
	log.Println("GetUserByIdResponse:")
	log.Printf("%+v\n\n", getUserByIdResponse)
	// SignIn
	signInResponse, err := client.SignIn(context.Background(), &pb.SignInRequest{
		ApiKey:   os.Getenv("API_KEY"),
		UserId:   TEST_USER_ID,
		Password: TEST_USER_PASSWORD,
	})
	if err != nil {
		panic(err)
	}
	log.Println("SignInResponse:")
	log.Printf("%+v\n\n", signInResponse)
	token := signInResponse.GetToken()
	// ChangePassword
	newPassword := "newPassword"
	changePasswordResponse, err := client.ChangePassword(context.Background(), &pb.ChangePasswordRequest{
		ApiKey:          os.Getenv("API_KEY"),
		Token:           token,
		CurrentPassword: TEST_USER_PASSWORD,
		NewPassword:     newPassword,
	})
	if err != nil {
		panic(err)
	}
	log.Println("ChangePasswordResponse:")
	log.Printf("%+v\n\n", changePasswordResponse)
	// DELETE
	deleteUserResponse, err := client.Delete(context.Background(), &pb.DeleteUserRequest{
		ApiKey:   os.Getenv("API_KEY"),
		Token:    token,
		Password: newPassword,
	})
	if err != nil {
		panic(err)
	}
	log.Println("DeleteUserResponse:")
	log.Printf("%+v\n\n", deleteUserResponse)
}
```

## client/pb/pb.go
```go
package pb

import (
	"fmt"
	"log"
	"os"

	grpc "google.golang.org/grpc"
)

var Conn *grpc.ClientConn

func init() {
	conn, err := grpc.Dial(os.Getenv("BACKEND_HOST"), grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to server")
	fmt.Println()
	Conn = conn
}
```

## client/proto/user.proto
```proto
syntax = "proto3";

package pb;

option go_package = "github.com/szlove/gogrpc/client/pb";

import "google/protobuf/timestamp.proto";

message SignUpRequest {
	string api_key  = 1;
	string user_id  = 2;
	string password = 3;
	string name     = 4;
	string email    = 5;
}

message SignUpResponse {
	string message = 1;
	string user_id = 2;
}

message GetUserByIdRequest {
	string api_key = 1;
	string user_id = 2;
}

message GetUserByIdResponse {
	string                    id         = 1;
	string                    name       = 2;
	string                    email      = 3;
	google.protobuf.Timestamp created_at = 4;
}

message SignInRequest {
	string api_key  = 1;
	string user_id  = 2;
	string password = 3;
}

message SignInResponse {
	string token = 2;
}

message ChangePasswordRequest {
	string api_key          = 1;
	string token            = 2;
	string current_password = 3;
	string new_password     = 4;
}

message ChangePasswordResponse {
	string message = 1;
}

message DeleteUserRequest {
	string api_key  = 1;
	string token    = 2;
	string password = 3;
}

message DeleteUserResponse {
	string message = 1;
}

service User {
	rpc SignUp(SignUpRequest) returns (SignUpResponse) {}
	rpc GetUserById(GetUserByIdRequest) returns (GetUserByIdResponse) {}
	rpc SignIn(SignInRequest) returns (SignInResponse) {}
	rpc ChangePassword(ChangePasswordRequest) returns (ChangePasswordResponse) {}
	rpc Delete(DeleteUserRequest) returns (DeleteUserResponse) {}
}
```
