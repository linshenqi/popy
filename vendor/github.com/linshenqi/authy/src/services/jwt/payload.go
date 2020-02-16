package jwt

import "github.com/dgrijalva/jwt-go"

const (
	RequestFailed = "JwtRequestFailed"
)

type Response struct {
	Token string `json:"token"`
}

type Request struct {
	Token  string        `json:"token"`
	Claims jwt.MapClaims `json:"claims"`
}
