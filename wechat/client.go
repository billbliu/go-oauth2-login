package wechat

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type WechatCfg struct {
	Token       string
	Appid       string
	Appsecret   string
	ExpiresTime int
}

type Client struct {
	hc *http.Client

	// 应用appID
	AppID string
	// 应用appSecret
	AppSecret string
	// 应用配置的token
	AppToken string
	// 授权成功后微信回调接口
	RedirectURL string
	// 二维码有效时长s
	QrValidTime int

	AppAccessToken *AppAccessToken

	// 获取应用授权token url
	AppAccessTokenURL string
	// 获取二维码ticket url
	QrTicketURL string
	// 用户授权url
	UserAuthorizeURL string
	// 获取用户授权token url
	UserAccessTokenURL string
	// 获取用户信息url
	UserInfoURL string

	Lang WechatLangType
	// 请求资源范围，多个空格隔开
	Scopes string
}

type WechatLangType string

const (
	WECHAT_LANG_CN WechatLangType = "cn"
	WECHAT_LANG_EN WechatLangType = "en"
)

// New creates a new Wechat Login Client
func New(appID, appSecret, appToken, redirectURL string, qrValidTime int, lang WechatLangType) *Client {
	if qrValidTime == 0 {
		qrValidTime = 60
	}
	client := &Client{
		hc: http.DefaultClient,

		AppID:       appID,
		AppSecret:   appSecret,
		AppToken:    appToken,
		RedirectURL: redirectURL,
		QrValidTime: qrValidTime,

		AppAccessToken: &AppAccessToken{
			AccessToken: "",
			ExpiresTime: 0,
			Time:        time.Now(),
		},

		AppAccessTokenURL: "https://api.weixin.qq.com/cgi-bin/token",
		QrTicketURL:       "https://api.weixin.qq.com/cgi-bin/qrcode/create",

		UserAuthorizeURL:   "https://open.weixin.qq.com/connect/oauth2/authorize",
		UserAccessTokenURL: "https://api.weixin.qq.com/sns/oauth2/access_token",
		UserInfoURL:        "https://api.weixin.qq.com/sns/userinfo",

		Lang:   lang,
		Scopes: "snsapi_login",
	}

	if err := client.RefreshAppAccessToken(); err != nil {
		log.Println("RefreshAT err:", err)
	}
	return client

}

// 签名验证(是否相同)
func (c *Client) VerifySignature(vp VerifyParams) bool {
	// 构造匹配字段
	strs := []string{c.AppToken, vp.Timestamp, vp.Nonce}
	// 按字典序排列后拼接成一个字符串
	sort.Strings(strs)
	str := strings.Join(strs, "")
	// 对拼接后的字符串进行 SHA1 加密
	hash := sha1.New()
	hash.Write([]byte(str))
	hashed := fmt.Sprintf("%x", hash.Sum(nil))
	// 加密结果与 signature 比较
	return hashed == vp.Signature
}

// AppAccessToken 刷新应用AccessToken
func (c *Client) RefreshAppAccessToken() error {
	// 先判断上次获取的是否超时
	duration := time.Since(c.AppAccessToken.Time)
	durationInSeconds := int(duration.Seconds())
	if durationInSeconds < (c.AppAccessToken.ExpiresTime - 600) {
		return nil
	}
	return c.GetAppAccessToken()
}

func (c *Client) GetAppAccessTokenUrl() string {
	params := url.Values{}
	params.Add("grant_type", "client_credential")
	params.Add("appid", c.AppID)
	params.Add("secret", c.AppSecret)
	return fmt.Sprintf("%s?%s",
		c.AppAccessTokenURL, params.Encode())
}

// 获取普通access token
func (c *Client) GetAppAccessToken() error {
	resp, err := c.hc.Get(c.GetAppAccessTokenUrl())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// 如果响应结果包含错误错误码，返回错误信息
	if strings.Contains(string(body), "errcode") {
		return fmt.Errorf("wechat GetAppAccessToken response error: %s", string(body))
	}
	// 解析字符串
	err = json.Unmarshal(body, &c.AppAccessToken)
	if err != nil {
		return errors.New("GetAppAccessToken json Unmarshal fail")
	}
	// 设置成功获取时间
	c.AppAccessToken.Time = time.Now()
	return nil
}

// GetVaildAppAccessToken 获取应用accesstoken
func (c *Client) GetVaildAppAccessToken() (at string, err error) {
	if err := c.RefreshAppAccessToken(); err != nil {
		log.Println("GetVaildAppAccessToken err:", err)
	}
	return c.AppAccessToken.AccessToken, nil
}

func (c *Client) GetQrTicketURL(appAccessToken string) string {
	params := url.Values{}
	params.Add("access_token", appAccessToken)
	return fmt.Sprintf("%s?%s",
		c.QrTicketURL, params.Encode())
}

func (c *Client) GetQRTicket(codeType string, sceneId int) (string, error) {
	appAccessToken, err := c.GetVaildAppAccessToken()
	if err != nil {
		return "", err
	}

	// 构造请求数据
	param := &GetQRTicketReq{
		ExpireSeconds: c.QrValidTime,
		ActionName:    codeType, // QR码 类型
		ActionInfo: ActionInfo{
			Scene: Scene{
				SceneId: sceneId,
			},
		},
	}

	// 发送 post 请求获取响应
	JsonReq, err := json.Marshal(&param)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.GetQrTicketURL(appAccessToken), bytes.NewReader(JsonReq))
	if err != nil {
		return "", err
	}

	// 设置请求头 json格式
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var respData = GetQRTicketRes{}
	// 解析字符串
	err = json.Unmarshal(body, &respData)
	if err != nil {
		return "", errors.New("json unmarsha fail")
	}
	return respData.Ticket, nil
}

func (c *Client) GetAuthorizeURL(state string) string {
	params := url.Values{}
	params.Add("appid", c.AppID)
	params.Add("response_type", "code")
	params.Add("state", state)
	params.Add("scope", c.Scopes)
	params.Add("redirect_uri", c.RedirectURL)
	return fmt.Sprintf("%s?%s#wechat_redirect",
		c.UserAuthorizeURL, params.Encode())
	// return fmt.Sprintf("%s?appid=%s&redirect_uri=%s&response_type=code&state=%s&scope=snsapi_userinfo#wechat_redirect",
	// 	c.AuthURL, c.AppID, c.RedirectURL, state)
}

func (c *Client) GetUserAccessTokenUrl(code string) string {
	params := url.Values{}
	params.Add("appid", c.AppID)
	params.Add("secret", c.AppSecret)
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	return fmt.Sprintf("%s?%s", c.UserAccessTokenURL, params.Encode())
}

// GetUserAccessToken will go to Wepay and access access token about the user.
func (c *Client) GetUserAccessToken(code string) (*GetUserAccessTokenRes, string, error) {
	resp, err := c.hc.Get(c.GetUserAccessTokenUrl(code))

	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("wechat gettoken returns code: %d", resp.StatusCode)
	}

	var userToken GetUserAccessTokenRes
	if err = json.NewDecoder(resp.Body).Decode(&userToken); err != nil {
		return nil, "", err
	}
	if userToken.Code != 0 {
		return nil, "", fmt.Errorf("CODE: %d, MSG: %s", userToken.Code, userToken.Msg)
	}

	return &userToken, userToken.Openid, nil
}

func (c *Client) GetUserInfoUrl(accessToken, openid string) string {
	params := url.Values{}
	params.Add("access_token", accessToken)
	params.Add("openid", openid)
	params.Add("lang", string(c.Lang))
	return fmt.Sprintf("%s?%s", c.UserInfoURL, params.Encode())
}

// GetUserInfo will go to Wepay and access basic information about the user.
func (c *Client) GetUserInfo(accessToken *GetUserAccessTokenRes, openid string) (*GetUserInfoRes, error) {
	if accessToken.AccessToken == "" {
		// accessToken is still empty
		return nil, fmt.Errorf("wechat cannot get user information, accessToken is empty")
	}

	req, err := http.NewRequest("GET", c.GetUserInfoUrl(accessToken.AccessToken, openid), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wechat responded with a %d trying to fetch user information", resp.StatusCode)
	}

	var user GetUserInfoRes
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	if len(user.Msg) > 0 {
		return nil, fmt.Errorf("CODE: %d, MSG: %s", user.Code, user.Msg)
	}

	return &user, err
}
