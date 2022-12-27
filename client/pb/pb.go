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
