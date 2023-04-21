package env

import "os"

var Email, Password, Proxy, CHATGPT_API_PREFIX string

func init() {
	Email = os.Getenv("USER_EMAIL")
	if Email == "" {
		Email = "<openai_email>"
	}

	Password = os.Getenv("USER_PASSWORD")
	if Password == "" {
		Password = "<openai_password>"
	}

	Proxy = os.Getenv("PROXY")
	if Proxy == "" {
		Proxy = "socks5://127.0.0.1:7890"
	}
	CHATGPT_API_PREFIX = os.Getenv("CHATGPT_API_PREFIX")
	if CHATGPT_API_PREFIX == "" {
		CHATGPT_API_PREFIX = "https://ai.fakeopen.com"
	}
}
