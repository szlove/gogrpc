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
