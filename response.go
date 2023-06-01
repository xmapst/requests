package requests

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/xmapst/requests/tools"
	"github.com/xmapst/requests/websocket"
)

type Response struct {
	response  *http.Response
	webSocket *websocket.Conn
	ctx       context.Context
	cnl       context.CancelFunc
	content   []byte
	encoding  string
	disDecode bool
	disUnzip  bool
	filePath  string
}

type SseClient struct {
	reader *bufio.Reader
}
type Event struct {
	Data    string
	Event   string
	Id      string
	Retry   int
	Comment string
}

func newSseClient(rd io.Reader) *SseClient {
	return &SseClient{reader: bufio.NewReader(rd)}
}
func (obj *SseClient) Recv() (Event, error) {
	var event Event
	for {
		readStr, err := obj.reader.ReadString('\n')
		if err != nil || readStr == "\n" {
			return event, err
		}
		if strings.HasPrefix(readStr, "data: ") {
			event.Data += readStr[6 : len(readStr)-1]
		} else if strings.HasPrefix(readStr, "event: ") {
			event.Event = readStr[7 : len(readStr)-1]
		} else if strings.HasPrefix(readStr, "id: ") {
			event.Id = readStr[4 : len(readStr)-1]
		} else if strings.HasPrefix(readStr, "retry: ") {
			if event.Retry, err = strconv.Atoi(readStr[7 : len(readStr)-1]); err != nil {
				return event, err
			}
		} else if strings.HasPrefix(readStr, ": ") {
			event.Comment = readStr[2 : len(readStr)-1]
		} else {
			return event, errors.New("内容解析错误：" + readStr)
		}
	}
}

func (obj *Client) newResponse(ctx context.Context, cnl context.CancelFunc, r *http.Response, request_option RequestOption) (*Response, error) {
	response := &Response{response: r, ctx: ctx, cnl: cnl}
	if request_option.DisRead { // 是否预读
		return response, nil
	}
	if request_option.DisUnZip || r.Uncompressed { // 是否解压
		response.disUnzip = true
	}
	response.disDecode = request_option.DisDecode // 是否解码
	return response, response.read()              // 读取内容
}

type Cookies []*http.Cookie

// 返回cookies 的字符串形式
func (obj Cookies) String() string {
	cooks := []string{}
	for _, cook := range obj {
		cooks = append(cooks, fmt.Sprintf("%s=%s", cook.Name, cook.Value))
	}
	return strings.Join(cooks, "; ")
}

// Gets 获取符合key 条件的所有cookies
func (obj Cookies) Gets(name string) Cookies {
	var result Cookies
	for _, cook := range obj {
		if cook.Name == name {
			result = append(result, cook)
		}
	}
	return result
}

// Get 获取符合key 条件的cookies
func (obj Cookies) Get(name string) *http.Cookie {
	vals := obj.Gets(name)
	if i := len(vals); i == 0 {
		return nil
	} else {
		return vals[i-1]
	}
}

// GetVals 获取符合key 条件的所有cookies的值
func (obj Cookies) GetVals(name string) []string {
	var result []string
	for _, cook := range obj {
		if cook.Name == name {
			result = append(result, cook.Value)
		}
	}
	return result
}

// GetVal 获取符合key 条件的cookies的值
func (obj Cookies) GetVal(name string) string {
	vals := obj.GetVals(name)
	if i := len(vals); i == 0 {
		return ""
	} else {
		return vals[i-1]
	}
}

// Response 返回原始http.Response
func (obj *Response) Response() *http.Response {
	return obj.response
}

// WebSocket 返回websocket 对象,当发送websocket 请求时使用
func (obj *Response) WebSocket() *websocket.Conn {
	return obj.webSocket
}
func (obj *Response) SseClient() *SseClient {
	select {
	case <-obj.ctx.Done():
		return newSseClient(bytes.NewBuffer(obj.Content()))
	default:
		return newSseClient(obj)
	}
}

// Location 返回当前的Location
func (obj *Response) Location() (*url.URL, error) {
	return obj.response.Location()
}

// Cookies 返回这个请求的cookies
func (obj *Response) Cookies() Cookies {
	if obj.filePath != "" {
		return nil
	}
	return obj.response.Cookies()
}

// StatusCode 返回这个请求的状态码
func (obj *Response) StatusCode() int {
	if obj.filePath != "" {
		return 200
	}
	return obj.response.StatusCode
}

// Status 返回这个请求的状态
func (obj *Response) Status() string {
	if obj.filePath != "" {
		return "200 OK"
	}
	return obj.response.Status
}

// Url 返回这个请求的url
func (obj *Response) Url() *url.URL {
	if obj.filePath != "" {
		return nil
	}
	return obj.response.Request.URL
}

// Headers 返回response 的请求头
func (obj *Response) Headers() http.Header {
	if obj.filePath != "" {
		return http.Header{
			"Content-Type": []string{obj.ContentType()},
		}
	}
	return obj.response.Header
}

// Decode 对内容进行解码
func (obj *Response) Decode(encoding string) {
	if obj.encoding != encoding {
		obj.encoding = encoding
		obj.Content(tools.Decode(obj.Content(), encoding))
	}
}

// Map 尝试将内容解析成map
func (obj *Response) Map() map[string]any {
	var data map[string]any
	if err := json.Unmarshal(obj.Content(), &data); err != nil {
		return nil
	}
	return data
}

// Json 尝试将请求解析成json
func (obj *Response) Json(path ...string) gjson.Result {
	return tools.Any2json(obj.Content(), path...)
}

// Text 返回内容的字符串形式，也可设置内容
func (obj *Response) Text(val ...string) string {
	if len(val) > 0 {
		return tools.BytesToString(obj.Content(tools.StringToBytes(val[0])))
	}
	return tools.BytesToString(obj.Content())
}

// Content 返回内容的二进制，也可设置内容
func (obj *Response) Content(val ...[]byte) []byte {
	if len(val) > 0 {
		obj.content = val[0]
		return obj.content
	}
	if obj.webSocket != nil {
		return obj.content
	}
	select {
	case <-obj.ctx.Done():
	default:
		defer obj.Close()
		bytesWrite := bytes.NewBuffer(nil)
		_ = tools.CopyWitchContext(obj.ctx, bytesWrite, obj)
		obj.content = bytesWrite.Bytes()
	}
	return obj.content
}

// ContentType 获取headers 的Content-Type
func (obj *Response) ContentType() string {
	if obj.filePath != "" {
		return tools.GetContentTypeWithBytes(obj.content)
	}
	contentType := obj.response.Header.Get("Content-Type")
	if contentType == "" {
		contentType = tools.GetContentTypeWithBytes(obj.content)
	}
	return contentType
}

// ContentEncoding 获取headers 的Content-Encoding
func (obj *Response) ContentEncoding() string {
	if obj.filePath != "" {
		return ""
	}
	return obj.response.Header.Get("Content-Encoding")
}

// ContentLength 获取response 的内容长度
func (obj *Response) ContentLength() int64 {
	if obj.filePath != "" {
		return int64(len(obj.content))
	}
	if obj.response.ContentLength >= 0 {
		return obj.response.ContentLength
	}
	return int64(len(obj.content))
}

func (obj *Response) defaultDecode() bool {
	return strings.Contains(obj.ContentType(), "html")
}

func (obj *Response) Read(con []byte) (int, error) { // 读取body
	select {
	case <-obj.ctx.Done():
		return 0, obj.ctx.Err()
	default:
		return obj.response.Body.Read(con)
	}
}

func (obj *Response) read() error { // 读取body,对body 解压，解码操作
	defer obj.Close()
	var body *bytes.Buffer
	var err error
	body = bytes.NewBuffer(nil)
	err = tools.CopyWitchContext(obj.response.Request.Context(), body, obj.response.Body)
	if err != nil {
		return errors.New("io.Copy error: " + err.Error())
	}
	if !obj.disUnzip {
		if body, err = tools.ZipDecode(obj.ctx, body, obj.ContentEncoding()); err != nil {
			return errors.New("gzip NewReader error: " + err.Error())
		}
	}
	if !obj.disDecode && obj.defaultDecode() {
		if content, encoding, err := tools.CharSet(body.Bytes(), obj.ContentType()); err == nil {
			obj.content, obj.encoding = content, encoding
		} else {
			obj.content = body.Bytes()
		}
	} else {
		obj.content = body.Bytes()
	}
	return nil
}

// Close 关闭response ,当disRead 为true 请一定要手动关闭
func (obj *Response) Close() error {
	if obj.cnl != nil {
		defer obj.cnl()
	}
	if obj.webSocket != nil {
		obj.webSocket.Close("close")
	}
	if obj.response != nil && obj.response.Body != nil {
		_ = tools.CopyWitchContext(obj.ctx, io.Discard, obj.response.Body)
		return obj.response.Body.Close()
	}
	return nil
}
