package wechat

import (
	"golang.org/x/oauth2"
)

// Endpoint is Wechat's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://open.weixin.qq.com/connect/oauth2/authorize",
	TokenURL: "https://api.weixin.qq.com/sns/oauth2/access_token",
}

type UserInfo struct {
	Openid    string `json:"openid"`
	Nickname  string `json:"nickname"`
	Sex       int    `json:"sex"`
	Province  string `json:"province"`
	City      string `json:"city"`
	Country   string `json:"country"`
	AvatarURL string `json:"headimgurl"`
	Unionid   string `json:"unionid"`
	Code      int    `json:"errcode"`
	Msg       string `json:"errmsg"`
}
