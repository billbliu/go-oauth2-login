package wechat

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/billbliu/gooauth"
	"golang.org/x/oauth2"
)

const (
	ScopeSnsapiLogin = "snsapi_login"
	UserInfoURL      = "https://api.weixin.qq.com/sns/userinfo"
)

type Provider struct {
	providerType gooauth.ProviderType
	config       *oauth2.Config
	httpClient   *http.Client
	Lang         WechatLangType

	UserInfoURL string
}

type WechatLangType string

const (
	WECHAT_LANG_CN WechatLangType = "cn"
	WECHAT_LANG_EN WechatLangType = "en"
)

// New creates a new Wechat provider, and sets up important connection details.
// You should always call `wechat.New` to get a new Provider. Never try to create one manually.
func New(clientID, clientSecret, redirectURL string, lang WechatLangType) *Provider {
	p := &Provider{
		providerType: gooauth.PROVIDER_WECHAT,
		Lang:         lang,
		UserInfoURL:  UserInfoURL,
	}

	c := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     Endpoint,
		Scopes:       []string{},
	}
	c.Scopes = append(c.Scopes, ScopeSnsapiLogin)

	p.config = c
	return p
}

// ProviderType is the type used to retrieve this provider later.
func (p *Provider) ProviderType() gooauth.ProviderType {
	return p.providerType
}

func (p *Provider) FetchToken(code string) (*oauth2.Token, string, error) {
	params := url.Values{}
	params.Add("appid", p.config.ClientID)
	params.Add("secret", p.config.ClientSecret)
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	url := fmt.Sprintf("%s?%s", p.config.Endpoint.TokenURL, params.Encode())
	resp, err := p.client().Get(url)

	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("wechat /gettoken returns code: %d", resp.StatusCode)
	}

	obj := struct {
		AccessToken string        `json:"access_token"`
		ExpiresIn   time.Duration `json:"expires_in"`
		Openid      string        `json:"openid"`
		Code        int           `json:"errcode"`
		Msg         string        `json:"errmsg"`
	}{}
	if err = json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return nil, "", err
	}
	if obj.Code != 0 {
		return nil, "", fmt.Errorf("CODE: %d, MSG: %s", obj.Code, obj.Msg)
	}

	token := &oauth2.Token{
		AccessToken: obj.AccessToken,
		Expiry:      time.Now().Add(obj.ExpiresIn * time.Second),
	}

	return token, obj.Openid, nil
}

// FetchUser will go to Wepay and access basic information about the user.
func (p *Provider) FetchUser(token *oauth2.Token, openid string) (gooauth.User, error) {
	user := gooauth.User{
		AccessToken:  token.AccessToken,
		ProviderType: p.ProviderType(),
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}

	if user.AccessToken == "" {
		// token AccessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerType)
	}

	params := url.Values{}
	params.Add("access_token", token.AccessToken)
	params.Add("openid", openid)
	params.Add("lang", string(p.Lang))

	url := fmt.Sprintf("%s?%s", p.UserInfoURL, params.Encode())

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return user, err
	}
	resp, err := p.client().Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerType, resp.StatusCode)
	}

	err = p.userFromReader(resp.Body, &user)
	return user, err
}

func (p *Provider) client() *http.Client {
	return gooauth.HTTPClientWithFallBack(p.httpClient)
}

func (p *Provider) userFromReader(r io.Reader, user *gooauth.User) error {
	u := UserInfo{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	if len(u.Msg) > 0 {
		return fmt.Errorf("CODE: %d, MSG: %s", u.Code, u.Msg)
	}

	user.Email = fmt.Sprintf("%s@wechat.com", u.Openid)
	user.Name = u.Nickname
	user.UserID = u.Openid
	user.NickName = u.Nickname
	user.Location = u.City
	user.AvatarURL = u.AvatarURL
	user.RawData = map[string]interface{}{
		"Unionid": u.Unionid,
	}
	return nil
}
