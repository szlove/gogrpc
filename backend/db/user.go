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
