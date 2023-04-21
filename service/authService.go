package service

import (
	"helix/auth"
	"helix/env"
)

func GetAccessToken(email string, password string) (*auth.AccessToken, error) {
	auth, err := auth.NewAuthenticator(email, password, env.Proxy, env.CHATGPT_API_PREFIX)
	if err != nil {
		return nil, err
	}
	err = auth.PartOne(auth.CreateLoginUrl())
	if err != nil {
		return nil, err
	}
	token, err := auth.GetToken()
	if err != nil {
		return nil, err
	}
	return token, nil
}
