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
