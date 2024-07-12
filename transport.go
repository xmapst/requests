package requests

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/xmapst/requests/http2"
)

func newHttpTransport(sessionOption ClientOption, dialCli *DialClient) *http.Transport {
	t := &http.Transport{
		MaxIdleConns:        655350,
		MaxConnsPerHost:     655350,
		MaxIdleConnsPerHost: 655350,
		ProxyConnectHeader: http.Header{
			"User-Agent": []string{UserAgent},
		},
		TLSHandshakeTimeout:   time.Second * time.Duration(sessionOption.TLSHandshakeTimeout),
		ResponseHeaderTimeout: time.Second * time.Duration(sessionOption.ResponseHeaderTimeout),
		DisableKeepAlives:     sessionOption.DisAlive,
		DisableCompression:    sessionOption.DisCompression,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		IdleConnTimeout:       time.Duration(sessionOption.IdleConnTimeout) * time.Second, // 空闲连接在连接池中的超时时间
		DialContext:           dialCli.requestHttpDialContext,
		DialTLSContext:        dialCli.requestHttpDialTlsContext,
		ForceAttemptHTTP2:     true,
		Proxy: func(r *http.Request) (*url.URL, error) {
			ctxData := r.Context().Value(keyPrincipalID).(*reqCtxData)
			ctxData.url = r.URL
			if ctxData.disProxy || ctxData.ja3 { // 关闭代理或ja3 走自实现代理
				return nil, nil
			}
			if ctxData.proxy != nil {
				ctxData.isCallback = true // 官方代理实现
			}
			return ctxData.proxy, nil
		},
	}
	if sessionOption.H2Ja3 || sessionOption.H2Ja3Spec.IsSet() {
		t.TLSNextProto = map[string]func(authority string, c *tls.Conn) http.RoundTripper{
			"h2": http2.Upg{
				H2Ja3Spec:      sessionOption.H2Ja3Spec,
				DialTLSContext: dialCli.requestHttp2DialTlsContext,
			}.UpgradeFn,
		}
	}
	return t
}
