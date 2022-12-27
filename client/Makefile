.PHONY:
	protoc clear

protoc:
	protoc --proto_path=proto \
	--go_out=pb --go_opt=paths=source_relative \
	--go-grpc_out=pb --go-grpc_opt=paths=source_relative \
	proto/*.proto

clear:
	rm pb/*.pb.go
