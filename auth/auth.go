package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"io"
	"io/ioutil"
	"net/url"
	"regexp"
	"strings"
)

const ERR_MSG = "Location: %s \nStatusCode: %v \nMsg: %s "

type Authenticator struct {
	EmailAddress string
	Password     string
	Proxy        string
	Client       tls_client.HttpClient
	AccessToken  string
	UserAgent    string
	Gateway      string
	URL          string
	CodeVerifier string
}

func (auth *Authenticator) URLEncode(str string) string {
	return url.QueryEscape(str)
}
func NewAuthenticator(emailAddress string, password string, proxy string, gateway string) (*Authenticator, error) {
	auth := &Authenticator{
		EmailAddress: emailAddress,
		Password:     password,
		Gateway:      gateway,
		UserAgent:    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
	}
	jar := tls_client.NewCookieJar()
	jar.SetCookies(
		&url.URL{Scheme: "https", Host: "chat.openai.com"},
		[]*http.Cookie{},
	)
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(20),
		tls_client.WithClientProfile(tls_client.Chrome_110),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar), // create cookieJar instance and pass it as argument
		// Proxy
		tls_client.WithProxyUrl(proxy),
	}
	auth.Client, _ = tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	return auth, nil

}
func GenerateCodeVerifier() string {
	// 生成 32 字节的随机字节序列
	b := make([]byte, 32)
	rand.Read(b)
	// 对随机字节序列进行 Base64 编码

	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// 生成指定长度的随机字符串
func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func codeChallenge(codeVerifier string) string {

	// 对 code_verifier 进行 SHA256 哈希并进行 Base64 编码
	// 根据 OAuth 2.0 规范，code_challenge 的值必须使用 code_verifier 的 SHA256 哈希值，并进行 Base64 编码
	sha256Hash := sha256.Sum256([]byte(codeVerifier))
	encoded := base64.URLEncoding.EncodeToString(sha256Hash[:])
	return strings.TrimRight(encoded, "=")
}
func (auth *Authenticator) CreateLoginUrl() string {
	baseURL := "https://auth0.openai.com/authorize"
	values := url.Values{}
	values.Set("client_id", "DRivsnm2Mu42T3KOpqdtwB3NYviHYzwD")
	values.Set("audience", "https://api.openai.com/v1")
	values.Set("redirect_uri", "https://platform.openai.com/auth/callback")
	values.Set("max_age", "0")
	values.Set("scope", "openid profile email offline_access")
	values.Set("response_type", "code")
	values.Set("response_mode", "query")
	values.Set("state", codeChallenge(generateRandomString(32)))
	values.Set("nonce", codeChallenge(generateRandomString(32)))
	auth.CodeVerifier = GenerateCodeVerifier()
	challenge := codeChallenge(auth.CodeVerifier)
	values.Set("code_challenge", challenge)
	values.Set("code_challenge_method", "S256")
	values.Set("auth0Client", "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9")
	urlString := baseURL + "?" + values.Encode()
	return urlString
}

func (auth *Authenticator) PartOne(url string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf(ERR_MSG, "part_one", 0, err)
	}
	req.Header.Set("Host", "auth0.openai.com")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", auth.UserAgent)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", "https://chat.openai.com/")

	resp, err := auth.Client.Do(req)
	if err != nil {
		return fmt.Errorf(ERR_MSG, "_part_one", 0, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf(ERR_MSG, "__part_one", 0, err)
	}

	if resp.StatusCode == 302 || resp.StatusCode == 200 {
		stateRegex := regexp.MustCompile(`state=(.*)`)
		stateMatch := stateRegex.FindStringSubmatch(string(body))
		if len(stateMatch) < 2 {
			return fmt.Errorf(ERR_MSG, "___part_one", 0, "Could not find state in response")
		}

		state := strings.Split(stateMatch[1], `"`)[0]
		return auth.partThree(state)
	} else {
		return fmt.Errorf(ERR_MSG, "____part_one", resp.StatusCode, string(body))
	}
}

func (auth *Authenticator) partTwo(state string) error {
	url := fmt.Sprintf("https://auth0.openai.com/u/login/identifier?state=%s", state)
	emailURLEncoded := auth.URLEncode(auth.EmailAddress)

	payload := fmt.Sprintf(
		"state=%s&username=%s&js-available=false&webauthn-available=true&is-brave=false&webauthn-platform-available=true&action=default",
		state, emailURLEncoded,
	)

	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf(ERR_MSG, "partTwo", 0, err)
	}

	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("User-Agent", auth.UserAgent)
	req.Header.Set("Referer", fmt.Sprintf("https://auth0.openai.com/u/login/identifier?state=%s", state))
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := auth.Client.Do(req)
	if err != nil {
		return fmt.Errorf(ERR_MSG, "part_two", 0, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 || resp.StatusCode == 200 {
		return auth.partThree(state)
	} else {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf(ERR_MSG, "_part_two", resp.StatusCode, string(body))
	}
}

func (auth *Authenticator) partThree(state string) error {
	url := fmt.Sprintf("https://auth0.openai.com/u/login/identifier?state=%s", state)
	emailURLEncoded := auth.URLEncode(auth.EmailAddress)

	payload := fmt.Sprintf(
		"state=%s&username=%s&js-available=false&webauthn-available=true&is-brave=false&webauthn-platform-available=true&action=default",
		state, emailURLEncoded,
	)

	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf(ERR_MSG, "part_three", 0, err)
	}

	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("User-Agent", auth.UserAgent)
	req.Header.Set("Referer", fmt.Sprintf("https://auth0.openai.com/u/login/identifier?state=%s", state))
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := auth.Client.Do(req)
	if err != nil {
		return fmt.Errorf(ERR_MSG, "_part_three", 0, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 || resp.StatusCode == 200 {
		return auth.partFour(state)
	} else {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf(ERR_MSG, "__part_three", resp.StatusCode, string(body))

	}

}

func (auth *Authenticator) partFour(state string) error {
	url := fmt.Sprintf("https://auth0.openai.com/u/login/password?state=%s", state)
	emailURLEncoded := auth.URLEncode(auth.EmailAddress)
	passwordURLEncoded := auth.URLEncode(auth.Password)
	payload := fmt.Sprintf("state=%s&username=%s&password=%s&action=default", state, emailURLEncoded, passwordURLEncoded)

	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf(ERR_MSG, "part_four", 0, err)
	}

	req.Header.Set("Host", "auth0.openai.com")
	req.Header.Set("Origin", "https://auth0.openai.com")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("User-Agent", auth.UserAgent)
	req.Header.Set("Referer", fmt.Sprintf("https://auth0.openai.com/u/login/password?state=%s", state))
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := auth.Client.Do(req)
	if err != nil {
		return fmt.Errorf("part_five", 0, "", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 {
		redirectURL := resp.Header.Get("Location")
		return auth.partFive(state, redirectURL)
	} else {
		body := bytes.NewBuffer(nil)
		_, err1 := body.ReadFrom(resp.Body)
		if err1 != nil {
			return fmt.Errorf(ERR_MSG, "_part_four", 0, "", err1)
		}
		return fmt.Errorf(ERR_MSG, "__part_four", resp.StatusCode, body.String())
	}
}

func (auth *Authenticator) partFive(state string, redirectURL string) error {
	url := "https://auth0.openai.com" + redirectURL

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf(ERR_MSG, "part_six", 0, err)
	}
	req.Header.Set("Host", "auth0.openai.com")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", auth.UserAgent)
	req.Header.Set("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8")
	req.Header.Set("Referer", fmt.Sprintf("https://auth0.openai.com/u/login/password?state=%s", state))
	resp, err := auth.Client.Do(req)
	if err != nil {
		return fmt.Errorf(ERR_MSG, "_part_five", 0, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 {
		auth.URL = resp.Header.Get("Location")
		return nil
	} else {
		return fmt.Errorf(ERR_MSG, "__part_five", resp.StatusCode, resp.Status)
	}
}

type AccessToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (auth *Authenticator) GetToken() (*AccessToken, error) {
	reqUrl := "https://auth0.openai.com/oauth/token"

	headers := map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Connection":      "keep-alive",
		"User-Agent":      auth.UserAgent,
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
		"Content-type":    "application/json",
	}

	Url, _ := url.Parse(auth.URL)
	code := Url.Query().Get("code")
	fmt.Println("get code:", code)
	reqMap := make(map[string]string)
	reqMap["client_id"] = "DRivsnm2Mu42T3KOpqdtwB3NYviHYzwD"
	reqMap["grant_type"] = "authorization_code"
	reqMap["redirect_uri"] = "https://platform.openai.com/auth/callback"
	reqMap["code"] = code
	reqMap["code_verifier"] = auth.CodeVerifier
	data, _ := json.Marshal(reqMap)
	req, err := http.NewRequest("POST", reqUrl, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf(ERR_MSG, "part_six", 0, err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ERR_MSG, "_part_six", 0, err)
	}
	defer resp.Body.Close()

	all, err := io.ReadAll(resp.Body)
	var token AccessToken
	json.Unmarshal(all, &token)
	return &token, nil
}
