package requests

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"

	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"time"
	_ "unsafe"

	"github.com/dlclark/regexp2"
	"github.com/xmapst/requests/ja3"
	"github.com/xmapst/requests/tools"
	"github.com/xmapst/requests/websocket"

	"github.com/tidwall/gjson"
)

//go:linkname readCookies net/http.readCookies
func readCookies(h http.Header, filter string) []*http.Cookie

//go:linkname readSetCookies net/http.readSetCookies
func readSetCookies(h http.Header) []*http.Cookie

// 支持json,map,[]string,http.Header,string
func ReadCookies(val any) Cookies {
	switch cook := val.(type) {
	case string:
		return readCookies(http.Header{"Cookie": []string{cook}}, "")
	case http.Header:
		return readCookies(cook, "")
	case []string:
		return readCookies(http.Header{"Cookie": cook}, "")
	default:
		jsonData := tools.Any2json(cook)
		if jsonData.IsObject() {
			head := http.Header{}
			for k, vvs := range jsonData.Map() {
				if vvs.IsArray() {
					for _, vv := range vvs.Array() {
						head.Add(k, vv.String())
					}
				} else {
					head.Add(k, vvs.String())
				}
			}
			return readCookies(head, "")
		}
		return nil
	}
}

func ReadSetCookies(val any) Cookies {
	switch cook := val.(type) {
	case string:
		return readSetCookies(http.Header{"Set-Cookie": []string{cook}})
	case http.Header:
		return readSetCookies(cook)
	case []string:
		return readSetCookies(http.Header{"Set-Cookie": cook})
	default:
		jsonData := tools.Any2json(cook)
		if jsonData.IsObject() {
			head := http.Header{}
			for k, vvs := range jsonData.Map() {
				if vvs.IsArray() {
					for _, vv := range vvs.Array() {
						head.Add(k, vv.String())
					}
				} else {
					head.Add(k, vvs.String())
				}
			}
			return readSetCookies(head)
		}
		return nil
	}
}

var UserAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36`
var AcceptLanguage = `"zh-CN,zh;q=0.9"`

// 请求操作========================================================================= start
var defaultHeaders = http.Header{
	"Accept-Encoding": []string{"gzip, deflate, br"},
	"Accept":          []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
	"Accept-Language": []string{AcceptLanguage},
	"User-Agent":      []string{UserAgent},
}

const keyPrincipalID = "gospiderContextData"

var (
	ErrFatal = errors.New("致命错误")
)

type reqCtxData struct {
	ja3Spec     ja3.ClientHelloSpec
	isCallback  bool
	proxy       *url.URL
	url         *url.URL
	host        string
	redirectNum int
	disProxy    bool
	ws          bool
	ja3         bool
}

// File 构造一个文件
type File struct {
	Key     string // 字段的key
	Name    string // 文件名
	Content []byte // 文件的内容
	Type    string // 文件类型
}

// RequestOption 请求参数选项
type RequestOption struct {
	Method        string   // method
	Url           *url.URL // 请求的url
	Host          string   // 网站的host
	Proxy         string   // 代理,支持http,https,socks5协议代理,例如：http://127.0.0.1:7005
	Timeout       int64    // 请求超时时间
	Headers       any      // 请求头,支持：json,map，header
	Cookies       any      // cookies,支持json,map,str
	Files         []File   // 文件
	Params        any      // url 中的参数，用以拼接url,支持json,map
	Form          any      // 发送multipart/form-data,适用于文件上传,支持json,map
	Data          any      // 发送application/x-www-form-urlencoded,适用于key,val,支持string,[]bytes,json,map
	body          io.Reader
	Body          io.Reader
	Json          any                                         // 发送application/json,支持：string,[]bytes,json,map
	Text          any                                         // 发送text/xml,支持string,[]bytes,json,map
	Raw           any                                         // 不设置context-type,支持string,[]bytes,json,map
	TempData      any                                         // 临时变量，用于回调存储或自由度更高的用法
	DisCookie     bool                                        // 关闭cookies管理,这个请求不用cookies池
	DisDecode     bool                                        // 关闭自动解码
	DisProxy      bool                                        // 是否关闭代理,强制关闭代理
	Ja3           bool                                        // 是否开启ja3
	Ja3Spec       ja3.ClientHelloSpec                         // 指定ja3Spec,使用ja3.CreateSpecWithStr 或者ja3.CreateSpecWithId 生成
	TryNum        int64                                       // 重试次数
	BeforCallBack func(context.Context, *RequestOption) error // 请求之前回调
	AfterCallBack func(context.Context, *Response) error      // 请求之后回调
	ErrCallBack   func(context.Context, error) bool           // 返回true 中断重试请求
	RedirectNum   int                                         // 重定向次数,小于零 关闭重定向
	DisAlive      bool                                        // 关闭长连接,这次请求不会复用之前的连接
	DisRead       bool                                        // 关闭默认读取请求体,不会主动读取body里面的内容，需用你自己读取
	DisUnZip      bool                                        // 关闭自动解压
	WsOption      websocket.Option                            // websocket option,使用websocket 请求的option

	converUrl   string
	contentType string
}

func newBody(val any, valType string, dataMap map[string][]string) (*bytes.Reader, error) {
	switch value := val.(type) {
	case gjson.Result:
		if !value.IsObject() {
			return nil, errors.New("body-type错误")
		}
		switch valType {
		case "json", "text", "raw":
			return bytes.NewReader(tools.StringToBytes(value.Raw)), nil
		case "data":
			tempVal := url.Values{}
			for kk, vv := range value.Map() {
				if vv.IsArray() {
					for _, v := range vv.Array() {
						tempVal.Add(kk, v.String())
					}
				} else {
					tempVal.Add(kk, vv.String())
				}
			}
			return bytes.NewReader(tools.StringToBytes(tempVal.Encode())), nil
		case "form", "params":
			for kk, vv := range value.Map() {
				kkvv := []string{}
				if vv.IsArray() {
					for _, v := range vv.Array() {
						kkvv = append(kkvv, v.String())
					}
				} else {
					kkvv = append(kkvv, vv.String())
				}
				dataMap[kk] = kkvv
			}
			return nil, nil
		default:
			return nil, errors.New("未知的content-type：" + valType)
		}
	case string:
		switch valType {
		case "json", "text", "data", "raw":
			return bytes.NewReader(tools.StringToBytes(value)), nil
		default:
			return nil, errors.New("未知的content-type：" + valType)
		}
	case []byte:
		switch valType {
		case "json", "text", "data", "raw":
			return bytes.NewReader(value), nil
		default:
			return nil, errors.New("未知的content-type：" + valType)
		}
	default:
		return newBody(tools.Any2json(value), valType, dataMap)
	}
}
func (obj *RequestOption) newHeaders() error {
	if obj.Headers == nil {
		obj.Headers = defaultHeaders.Clone()
		return nil
	}
	switch headers := obj.Headers.(type) {
	case http.Header:
		obj.Headers = headers.Clone()
		return nil
	case gjson.Result:
		if !headers.IsObject() {
			return errors.New("new headers error")
		}
		head := http.Header{}
		for kk, vv := range headers.Map() {
			if vv.IsArray() {
				for _, v := range vv.Array() {
					head.Add(kk, v.String())
				}
			} else {
				head.Add(kk, vv.String())
			}
		}
		obj.Headers = head
		return nil
	default:
		obj.Headers = tools.Any2json(headers)
		return obj.newHeaders()
	}
}
func (obj *RequestOption) newCookies() error {
	if obj.Cookies == nil {
		return nil
	}
	switch cookies := obj.Cookies.(type) {
	case Cookies:
		return nil
	case []*http.Cookie:
		obj.Cookies = Cookies(cookies)
		return nil
	case string:
		obj.Cookies = ReadCookies(cookies)
		return nil
	case gjson.Result:
		if !cookies.IsObject() {
			return errors.New("new cookies error")
		}
		cook := []*http.Cookie{}
		for kk, vv := range cookies.Map() {
			if vv.IsArray() {
				for _, v := range vv.Array() {
					cook = append(cook, &http.Cookie{
						Name:  kk,
						Value: v.String(),
					})
				}
			} else {
				cook = append(cook, &http.Cookie{
					Name:  kk,
					Value: vv.String(),
				})
			}
		}
		obj.Cookies = cook
		return nil
	default:
		obj.Cookies = tools.Any2json(cookies)
		return obj.newCookies()
	}
}
func (obj *RequestOption) optionInit() error {
	obj.converUrl = obj.Url.String()
	var err error
	// 构造body
	if obj.Raw != nil {
		if obj.body, err = newBody(obj.Raw, "raw", nil); err != nil {
			return err
		}
	} else if obj.Form != nil {
		dataMap := map[string][]string{}
		if obj.body, err = newBody(obj.Form, "form", dataMap); err != nil {
			return err
		}
		tempBody := bytes.NewBuffer(nil)
		writer := multipart.NewWriter(tempBody)
		for key, vals := range dataMap {
			for _, val := range vals {
				if err = writer.WriteField(key, val); err != nil {
					return err
				}
			}
		}
		escapeQuotes := strings.NewReplacer("\\", "\\\\", `"`, "\\\"")
		for _, file := range obj.Files {
			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, escapeQuotes.Replace(file.Key), escapeQuotes.Replace(file.Name)))
			if file.Type == "" {
				h.Set("Content-Type", "application/octet-stream")
			} else {
				h.Set("Content-Type", file.Type)
			}
			if wp, err := writer.CreatePart(h); err != nil {
				return err
			} else if _, err = wp.Write(file.Content); err != nil {
				return err
			}
		}
		if err = writer.Close(); err != nil {
			return err
		}
		obj.contentType = writer.FormDataContentType()
		obj.body = tempBody
	} else if obj.Data != nil {
		if obj.body, err = newBody(obj.Data, "data", nil); err != nil {
			return err
		}
		obj.contentType = "application/x-www-form-urlencoded"
	} else if obj.Json != nil {
		if obj.body, err = newBody(obj.Json, "json", nil); err != nil {
			return err
		}
		obj.contentType = "application/json"
	} else if obj.Text != nil {
		if obj.body, err = newBody(obj.Text, "text", nil); err != nil {
			return err
		}
		obj.contentType = "text/plain"
	}
	// 构造params
	if obj.Params != nil {
		dataMap := map[string][]string{}
		if _, err = newBody(obj.Params, "params", dataMap); err != nil {
			return err
		}
		pu := cloneUrl(obj.Url)
		puValues := pu.Query()
		for kk, vvs := range dataMap {
			for _, vv := range vvs {
				puValues.Add(kk, vv)
			}
		}
		pu.RawQuery = puValues.Encode()
		obj.converUrl = pu.String()
	}
	// 构造headers
	if err = obj.newHeaders(); err != nil {
		return err
	}
	if obj.Ja3Spec.IsSet() { // 有值
		obj.Ja3 = true
	}
	// 构造cookies
	return obj.newCookies()
}
func (obj *Client) newRequestOption(option RequestOption) (RequestOption, error) {
	if option.TryNum == 0 {
		option.TryNum = obj.TryNum
	}
	if option.BeforCallBack == nil {
		option.BeforCallBack = obj.BeforCallBack
	}
	if option.AfterCallBack == nil {
		option.AfterCallBack = obj.AfterCallBack
	}
	if option.ErrCallBack == nil {
		option.ErrCallBack = obj.ErrCallBack
	}
	if option.Headers == nil {
		if obj.Headers == nil {
			option.Headers = defaultHeaders.Clone()
		} else {
			option.Headers = obj.Headers
		}
	}
	if option.RedirectNum == 0 {
		option.RedirectNum = obj.RedirectNum
	}
	if option.Timeout == 0 {
		option.Timeout = obj.Timeout
	}
	if !option.DisAlive {
		option.DisAlive = obj.disAlive
	}
	if !option.DisCookie {
		option.DisCookie = obj.disCookie
	}
	if !option.DisDecode {
		option.DisDecode = obj.DisDecode
	}
	if !option.DisRead {
		option.DisRead = obj.DisRead
	}
	if !option.DisUnZip {
		option.DisUnZip = obj.DisUnZip
	}
	if !option.Ja3 {
		option.Ja3 = obj.ja3
	}
	if !option.Ja3Spec.IsSet() {
		option.Ja3Spec = obj.ja3Spec
	}
	var err error
	if con, ok := option.Json.(io.Reader); ok {
		if option.Json, err = io.ReadAll(con); err != nil {
			return option, err
		}
	}
	if con, ok := option.Text.(io.Reader); ok {
		if option.Text, err = io.ReadAll(con); err != nil {
			return option, err
		}
	}
	if con, ok := option.Data.(io.Reader); ok {
		if option.Data, err = io.ReadAll(con); err != nil {
			return option, err
		}
	}
	return option, err
}

func (obj *Client) RequestWithContext(preCtx context.Context, method string, href string, options ...RequestOption) (resp *Response, err error) {
	if obj == nil {
		return nil, errors.New("初始化client失败")
	}
	if preCtx == nil {
		preCtx = obj.ctx
	}
	var rawOption RequestOption
	if len(options) > 0 {
		rawOption = options[0]
	}
	if rawOption.Method == "" {
		rawOption.Method = method
	}
	if rawOption.Url == nil {
		if rawOption.Url, err = url.Parse(href); err != nil {
			return
		}
	}
	if rawOption.Body != nil {
		if rawOption.Raw, err = io.ReadAll(rawOption.Body); err != nil {
			return
		}
	}
	var optionBak RequestOption
	if optionBak, err = obj.newRequestOption(rawOption); err != nil {
		return
	}
	if optionBak.BeforCallBack == nil {
		if err = optionBak.optionInit(); err != nil {
			return
		}
	}
	// 开始请求
	var tryNum int64
	for tryNum = 0; tryNum <= optionBak.TryNum; tryNum++ {
		select {
		case <-obj.ctx.Done():
			obj.Close()
			return nil, errors.New("http client closed")
		case <-preCtx.Done():
			return nil, preCtx.Err()
		default:
			option := optionBak
			if option.BeforCallBack != nil {
				if err = option.BeforCallBack(preCtx, &option); err != nil {
					if errors.Is(err, ErrFatal) {
						return
					} else {
						continue
					}
				}
			}
			if err = option.optionInit(); err != nil {
				return
			}
			resp, err = obj.tempRequest(preCtx, option)
			if err != nil { // 有错误
				if errors.Is(err, ErrFatal) { // 致命错误直接返回
					return
				} else if option.ErrCallBack != nil && option.ErrCallBack(preCtx, err) { // 不是致命错误，有错误回调,错误回调true,直接返回
					return
				}
			} else if option.AfterCallBack == nil { // 没有错误，且没有回调，直接返回
				return
			} else if err = option.AfterCallBack(preCtx, resp); err != nil { // 没有错误，有回调，回调错误
				if errors.Is(err, ErrFatal) { // 致命错误直接返回
					return
				} else if option.ErrCallBack != nil && option.ErrCallBack(preCtx, err) { // 不是致命错误，有错误回调,错误回调true,直接返回
					return
				}
			} else { // 没有错误，有回调，没有回调错误，直接返回
				return
			}
		}
	}
	if err != nil { // 有错误直接返回错误
		return
	}
	return resp, errors.New("max try num")
}

// Request 发送请求
func (obj *Client) Request(method string, href string, options ...RequestOption) (resp *Response, err error) {
	return obj.RequestWithContext(context.Background(), method, href, options...)
}

// Get 发送GET请求
func (obj *Client) Get(href string, options ...RequestOption) (resp *Response, err error) {
	return obj.Request("GET", href, options...)
}

func verifyProxy(proxyUrl string) (*url.URL, error) {
	proxy, err := url.Parse(proxyUrl)
	if err != nil {
		return nil, err
	}
	switch proxy.Scheme {
	case "http", "socks5", "https":
		return proxy, nil
	default:
		return nil, tools.WrapError(ErrFatal, "不支持的代理协议")
	}
}
func finalFunc(r *Response) {
	r.Close()
}
func (obj *Client) tempRequest(preCtx context.Context, requestOption RequestOption) (response *Response, err error) {
	method := strings.ToUpper(requestOption.Method)
	href := requestOption.converUrl
	var reqs *http.Request
	// 构造ctxData
	ctxData := new(reqCtxData)
	ctxData.disProxy = requestOption.DisProxy
	ctxData.ja3 = requestOption.Ja3
	ctxData.ja3Spec = requestOption.Ja3Spec
	if requestOption.Proxy != "" { // 代理相关构造
		tempProxy, err := verifyProxy(requestOption.Proxy)
		if err != nil {
			return response, tools.WrapError(ErrFatal, err)
		}
		ctxData.proxy = tempProxy
	}
	if requestOption.RedirectNum != 0 { // 重定向次数
		ctxData.redirectNum = requestOption.RedirectNum
	}
	// 构造ctx,cnl
	var cancel context.CancelFunc
	var reqCtx context.Context
	if requestOption.Timeout > 0 { // 超时
		reqCtx, cancel = context.WithTimeout(context.WithValue(preCtx, keyPrincipalID, ctxData), time.Duration(requestOption.Timeout)*time.Second)
	} else {
		reqCtx, cancel = context.WithCancel(context.WithValue(preCtx, keyPrincipalID, ctxData))
	}
	defer func() {
		if err != nil {
			cancel()
			if response != nil {
				response.Close()
			}
		}
		if obj.Closed() {
			obj.Close()
		}
	}()
	// 创建request
	if requestOption.body != nil {
		reqs, err = http.NewRequestWithContext(reqCtx, method, href, requestOption.body)
	} else {
		reqs, err = http.NewRequestWithContext(reqCtx, method, href, nil)
	}
	if err != nil {
		return response, tools.WrapError(ErrFatal, err)
	}
	ctxData.url = reqs.URL
	ctxData.host = reqs.Host
	if reqs.URL.Scheme == "file" {
		regexp, err := regexp2.Compile(`^/+`, regexp2.RE2)
		if err != nil {
			return nil, err
		}
		filePath, err := regexp.Replace(reqs.URL.Path, "", -1, -1)
		if err != nil {
			return nil, err
		}
		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		cancel()
		return &Response{
			content:  fileContent,
			filePath: filePath,
		}, nil
	}
	// 判断ws
	switch reqs.URL.Scheme {
	case "ws":
		ctxData.ws = true
		reqs.URL.Scheme = "http"
	case "wss":
		ctxData.ws = true
		reqs.URL.Scheme = "https"
	}
	// 添加headers
	var headOk bool
	if reqs.Header, headOk = requestOption.Headers.(http.Header); !headOk {
		return response, tools.WrapError(ErrFatal, "headers 转换错误")
	}

	if reqs.Header.Get("Content-type") == "" && requestOption.contentType != "" {
		reqs.Header.Set("Content-Type", requestOption.contentType)
	}

	// host构造
	if requestOption.Host != "" {
		reqs.Host = requestOption.Host
	} else if reqs.Header.Get("Host") != "" {
		reqs.Host = reqs.Header.Get("Host")
	}
	// 添加cookies
	if requestOption.Cookies != nil {
		cooks, cookOk := requestOption.Cookies.(Cookies)
		if !cookOk {
			return response, tools.WrapError(ErrFatal, "cookies 转换错误")
		}
		for _, vv := range cooks {
			reqs.AddCookie(vv)
		}
	}
	// 开始发送请求
	var r *http.Response
	var err2 error
	if ctxData.ws {
		websocket.SetClientHeaders(reqs.Header, requestOption.WsOption)
	}
	r, err = obj.getClient(requestOption).Do(reqs)
	if r != nil {
		if ctxData.ws {
			requestOption.DisRead = true
			if r.StatusCode != 101 && err == nil {
				err = errors.New("statusCode not 101")
			}
		} else if r.Header.Get("Content-Type") == "text/event-stream" {
			requestOption.DisRead = true
		}
		r.Close = requestOption.DisAlive
		if response, err2 = obj.newResponse(reqCtx, cancel, r, requestOption); err2 != nil { // 创建 response
			return response, err2
		}
		if ctxData.ws && r.StatusCode == 101 {
			if response.webSocket, err2 = websocket.NewClientConn(r); err2 != nil { // 创建 websocket
				return response, err2
			}
		}
	}
	return response, err
}

var defaultClient, _ = NewClient(ClientOption{
	Ja3:   true,
	H2Ja3: true,
})

// Request 发送请求
func Request(method string, href string, options ...RequestOption) (resp *Response, err error) {
	return defaultClient.Request(method, href, options...)
}

// Get 发送GET请求
func Get(href string, options ...RequestOption) (resp *Response, err error) {
	return defaultClient.Request("GET", href, options...)
}

func RequestWithContext(preCtx context.Context, method string, href string, options ...RequestOption) (resp *Response, err error) {
	return defaultClient.RequestWithContext(preCtx, method, href, options...)
}
