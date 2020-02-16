package user

import (
	"encoding/json"
	"github.com/kataras/iris"
	"github.com/linshenqi/sptty"
)

func (s *Service) postAuth(ctx iris.Context) {
	req := RequestAuth{}
	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(ErrAuth, err.Error()))
		return
	}

	user, err := s.Auth(req)
	if err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(ErrAuth, err.Error()))
		return
	}

	body, _ := json.Marshal(user)
	_, _ = ctx.Write(body)
}

func (s *Service) postRegister(ctx iris.Context) {
	req := RequestRegister{}
	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(ErrRegister, err.Error()))
		return
	}

	user, err := s.UserRegister(req)
	if err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(ErrRegister, err.Error()))
		return
	}

	body, _ := json.Marshal(user)
	_, _ = ctx.Write(body)
}
