package wechat

import "time"

// 微信服务器验证
type VerifyParams struct {
	Signature string
	Timestamp string
	Nonce     string
	Echostr   string
}

// 应用的access token
type AppAccessToken struct {
	AccessToken string `json:"access_token"`
	ExpiresTime int    `json:"expires_in"`
	Time        time.Time
}

// 用户事件
type UserEvent struct {
	ToUserName   string `p:"ToUserName" xml:"ToUserName"`     // 开发者微信号
	FromUserName string `p:"FromUserName" xml:"FromUserName"` // 发送方账号（一个OpenID）
	CreateTime   int    `p:"CreateTime" xml:"CreateTime"`     // 消息创建时间（整型）
	MsgType      string `p:"MsgType" xml:"MsgType"`           // 消息类型，event,
	Event        string `p:"Event" xml:"Event"`               // 事件类型，subscribe（关注）, SCAN（已关注）
	EventKey     string `p:"EventKey" xml:"EventKey"`         // 事件KEY值，qrscene_为前缀，后面为二维码的参数值
	Ticket       string `p:"Ticket" xml:"Ticket"`             // 二维码的ticket，可用来换取二维码图片
}

// 网页授权用户的access token
type GetUserAccessTokenRes struct {
	AccessToken    string        `json:"access_token"`
	ExpiresIn      time.Duration `json:"expires_in"`
	RefreshToken   string        `json:"refresh_token"`
	Openid         string        `json:"openid"`
	Scope          string        `json:"scope"`
	IsSnapshotuser int           `json:"is_snapshotuser"`
	Unionid        string        `json:"unionid"`
	Code           int           `json:"errcode"`
	Msg            string        `json:"errmsg"`
}

// 用户信息
type GetUserInfoRes struct {
	Openid     string   `json:"openid"`
	Nickname   string   `json:"nickname"`
	Sex        int      `json:"sex"`
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Country    string   `json:"country"`
	Headimgurl string   `json:"headimgurl"`
	Privilege  []string `json:"privilege"`
	Unionid    string   `json:"unionid"`
	Code       int      `json:"errcode"`
	Msg        string   `json:"errmsg"`
}

type (
	// QR code 请求体
	GetQRTicketReq struct {
		ExpireSeconds int        `json:"expire_seconds"`
		ActionName    string     `json:"action_name"`
		ActionInfo    ActionInfo `json:"action_info"`
	}
	ActionInfo struct {
		Scene `json:"scene"`
	}
	Scene struct {
		SceneId int `json:"scene_id"`
	}
	// QR code 响应体
	GetQRTicketRes struct {
		Ticket        string `json:"ticket"`
		ExpireSeconds int    `json:"expire_seconds"`
		Url           string `json:"url"`
	}
)
