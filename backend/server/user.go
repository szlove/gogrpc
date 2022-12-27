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
