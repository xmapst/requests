package requests

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/xmapst/requests/ja3"
)

type ClientOption struct {
	GetProxy              func(ctx context.Context, url *url.URL) (string, error) // 根据url 返回代理，支持https,http,socks5 代理协议
	Proxy                 string                                                  // 设置代理,支持https,http,socks5 代理协议
	TLSHandshakeTimeout   time.Duration                                           // tls 超时时间,default:15
	ResponseHeaderTimeout int64                                                   // 第一个response headers 接收超时时间,default:30
	DisCookie             bool                                                    // 关闭cookies管理
	DisAlive              bool                                                    // 关闭长连接
	DisCompression        bool                                                    // 关闭请求头中的压缩功能
	LocalAddr             string                                                  // 本地网卡出口ip
	IdleConnTimeout       int64                                                   // 空闲连接在连接池中的超时时间,default:30
	KeepAlive             int64                                                   // keepalive保活检测定时,default:15
	DnsCacheTime          int64                                                   // dns解析缓存时间60*30
	DisDnsCache           bool                                                    // 是否关闭dns 缓存,影响dns 解析
	AddrType              AddrType                                                // 优先使用的addr 类型
	GetAddrType           func(string) AddrType                                   // 地址类型
	Dns                   string                                                  // dns
	Ja3                   bool                                                    // 开启ja3
	Ja3Spec               ja3.ClientHelloSpec                                     // 指定ja3Spec,使用ja3.CreateSpecWithStr 或者ja3.CreateSpecWithId 生成
	H2Ja3                 bool                                                    // 开启h2指纹
	H2Ja3Spec             ja3.H2Ja3Spec                                           // h2指纹
}
type Client struct {
	RedirectNum   int                                         // 重定向次数
	DisDecode     bool                                        // 关闭自动编码
	DisRead       bool                                        // 关闭默认读取请求体
	DisUnZip      bool                                        // 变比自动解压
	TryNum        int64                                       // 重试次数
	BeforCallBack func(context.Context, *RequestOption) error // 请求前回调的方法
	AfterCallBack func(context.Context, *Response) error      // 请求后回调的方法
	ErrCallBack   func(context.Context, error) bool           // 请求error回调
	Timeout       int64                                       // 请求超时时间
	Headers       any                                         // 请求头
	ja3           bool                                        // 开启ja3
	ja3Spec       ja3.ClientHelloSpec                         // 指定ja3Spec,使用ja3.CreateSpecWithStr 或者ja3.CreateSpecWithId 生成
	disCookie     bool
	disAlive      bool
	client        *http.Client
	baseTransport *http.Transport
	ctx           context.Context
	cnl           context.CancelFunc
}

// NewClientWithContext 新建一个请求客户端,发送请求必须创建哈
func NewClientWithContext(preCtx context.Context, clientOptinos ...ClientOption) (*Client, error) {
	var isG bool
	if preCtx == nil {
		preCtx = context.TODO()
	} else {
		isG = true
	}
	ctx, cnl := context.WithCancel(preCtx)
	var sessionOption ClientOption
	// 初始化参数
	if len(clientOptinos) > 0 {
		sessionOption = clientOptinos[0]
	}
	if sessionOption.IdleConnTimeout == 0 {
		sessionOption.IdleConnTimeout = 30
	}
	if sessionOption.KeepAlive == 0 {
		sessionOption.KeepAlive = 15
	}
	if sessionOption.TLSHandshakeTimeout == 0 {
		sessionOption.TLSHandshakeTimeout = 15
	}
	if sessionOption.ResponseHeaderTimeout == 0 {
		sessionOption.ResponseHeaderTimeout = 30
	}
	if sessionOption.DnsCacheTime == 0 {
		sessionOption.DnsCacheTime = 60 * 30
	}
	dialClient, err := newDail(DialOption{
		TLSHandshakeTimeout: sessionOption.TLSHandshakeTimeout,
		DnsCacheTime:        sessionOption.DnsCacheTime,
		GetProxy:            sessionOption.GetProxy,
		Proxy:               sessionOption.Proxy,
		KeepAlive:           sessionOption.KeepAlive,
		LocalAddr:           sessionOption.LocalAddr,
		AddrType:            sessionOption.AddrType,
		GetAddrType:         sessionOption.GetAddrType,
		DisDnsCache:         sessionOption.DisDnsCache,
		Dns:                 sessionOption.Dns,
	})
	if err != nil {
		cnl()
		return nil, err
	}
	var client http.Client
	// 创建cookiesjar
	var jar *cookiejar.Jar
	if !sessionOption.DisCookie {
		if jar, err = cookiejar.New(nil); err != nil {
			cnl()
			return nil, err
		}
	}
	baseTransport := newHttpTransport(sessionOption, dialClient)
	client.Transport = baseTransport.Clone()
	client.Jar = jar
	client.CheckRedirect = checkRedirect
	result := &Client{
		ctx:           ctx,
		cnl:           cnl,
		client:        &client,
		baseTransport: &baseTransport,
		disAlive:      sessionOption.DisAlive,
		disCookie:     sessionOption.DisCookie,
		ja3:           sessionOption.Ja3,
		ja3Spec:       sessionOption.Ja3Spec,
	}
	if isG {
		go func() {
			<-result.ctx.Done()
			result.Close()
		}()
	}
	return result, nil
}

// NewClient 新建一个请求客户端,发送请求必须创建哈
func NewClient(clientOptinos ...ClientOption) (*Client, error) {
	return NewClientWithContext(context.Background(), clientOptinos...)
}
func checkRedirect(req *http.Request, via []*http.Request) error {
	ctxData := req.Context().Value(keyPrincipalID).(*reqCtxData)
	if ctxData.redirectNum == 0 || ctxData.redirectNum >= len(via) {
		ctxData.url = req.URL
		ctxData.host = req.Host
		return nil
	}
	return http.ErrUseLastResponse
}

func (obj *Client) clone(requestOption RequestOption) *http.Client {
	cli := &http.Client{
		CheckRedirect: obj.client.CheckRedirect,
	}
	if !requestOption.DisCookie && obj.client.Jar != nil {
		cli.Jar = obj.client.Jar
	}
	if !requestOption.DisAlive {
		cli.Transport = obj.client.Transport
	} else {
		cli.Transport = obj.baseTransport.Clone()
	}
	return cli
}

// Clone 克隆请求客户端,返回一个由相同option 构造的客户端，但是不会克隆:连接池,ookies
func (obj *Client) Clone() *Client {
	result := *obj
	result.client.Transport = result.baseTransport.Clone()
	return &result
}

// Reset 重置客户端至初始状态
func (obj *Client) Reset() error {
	if obj.client.Jar != nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return err
		}
		obj.client.Jar = jar
	}
	obj.CloseIdleConnections()
	obj.client.Transport = obj.baseTransport.Clone()
	return nil
}

// Close 关闭客户端
func (obj *Client) Close() {
	obj.CloseIdleConnections()
	obj.cnl()
}
func (obj *Client) Closed() bool {
	select {
	case <-obj.ctx.Done():
		return true
	default:
		return false
	}
}

// CloseIdleConnections 关闭客户端中的空闲连接
func (obj *Client) CloseIdleConnections() {
	obj.client.CloseIdleConnections()
	obj.baseTransport.CloseIdleConnections()
}

// Cookies 返回url 的cookies,也可以设置url 的cookies
func (obj *Client) Cookies(href string, cookies ...*http.Cookie) Cookies {
	if obj.client.Jar == nil {
		return nil
	}
	u, err := url.Parse(href)
	if err != nil {
		return nil
	}
	obj.client.Jar.SetCookies(u, cookies)
	return obj.client.Jar.Cookies(u)
}

// ClearCookies 清除cookies
func (obj *Client) ClearCookies() error {
	var jar *cookiejar.Jar
	var err error
	jar, err = cookiejar.New(nil)
	if err != nil {
		return err
	}
	obj.client.Jar = jar
	obj.client.Jar = jar
	return nil
}
func (obj *Client) getClient(requestOption RequestOption) *http.Client {
	if requestOption.DisAlive || requestOption.DisCookie {
		tempClient := obj.clone(requestOption)
		return tempClient
	} else {
		return obj.client
	}
}
