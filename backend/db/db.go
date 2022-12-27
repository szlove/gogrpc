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
