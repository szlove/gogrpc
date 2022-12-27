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
