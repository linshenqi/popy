package jwt

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/kataras/iris"
	"github.com/linshenqi/sptty"
)

func (s *Service) Signer(ctx iris.Context) {
	claims := jwt.MapClaims{}
	err := ctx.ReadJSON(&claims)
	if err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(RequestFailed, err.Error()))
		return
	}

	token, err := s.Sign(claims)
	if err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(RequestFailed, err.Error()))
		return
	}

	body, _ := json.Marshal(Response{
		Token: token,
	})

	ctx.StatusCode(iris.StatusOK)
	_, _ = ctx.Write(body)
}

func (s *Service) Auther(ctx iris.Context) {
	req := Request{}
	err := ctx.ReadJSON(&req)
	if err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(RequestFailed, err.Error()))
		return
	}

	claims, err := s.Validate(req.Claims, req.Token)
	if err != nil {
		ctx.StatusCode(iris.StatusConflict)
		_, _ = ctx.Write(sptty.NewRequestError(RequestFailed, err.Error()))
		return
	}

	ctx.StatusCode(iris.StatusOK)
	sBody, _ := json.Marshal(claims)
	_, _ = ctx.Write(sBody)
}

func (s *Service) Parser(ctx iris.Context) {
	ctx.Header("content-type", "application/json")
	req := Request{}
	err := ctx.ReadJSON(&req)
	if err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(RequestFailed, err.Error()))
		return
	}

	claims, err := s.Parse(req.Token)
	if err != nil {
		ctx.StatusCode(iris.StatusConflict)
		return
	}

	ctx.StatusCode(iris.StatusOK)
	sBody, _ := json.Marshal(claims)
	_, _ = ctx.Write(sBody)
}
