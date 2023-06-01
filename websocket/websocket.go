package websocket

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	_ "unsafe"

	"github.com/xmapst/requests/tools"
	"golang.org/x/exp/slices"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

type compressionOptions struct {
	clientNoContextTakeover bool
	serverNoContextTakeover bool
}
type CompressionOptions = compressionOptions
type connConfig struct {
	subprotocol    string
	rwc            io.ReadWriteCloser
	client         bool
	copts          *compressionOptions
	flateThreshold int

	br *bufio.Reader
	bw *bufio.Writer
}

//go:linkname newConn nhooyr.io/websocket.newConn
func newConn(cfg connConfig) *websocket.Conn

//go:linkname getBufioReader nhooyr.io/websocket.getBufioReader
func getBufioReader(r io.Reader) *bufio.Reader

//go:linkname getBufioWriter nhooyr.io/websocket.getBufioWriter
func getBufioWriter(w io.Writer) *bufio.Writer

func selectSubprotocol(r *http.Request, subprotocols []string) string {
	for _, protocols := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(protocols, ",") {
			protocol = strings.TrimSpace(protocol)
			if len(subprotocols) == 0 || slices.Index(subprotocols, protocol) != -1 {
				return protocol
			}
		}
	}
	return ""
}

type Conn struct {
	rwc    io.ReadWriteCloser
	conn   *websocket.Conn
	option Option
}
type Option struct {
	Subprotocols         []string        // Subprotocols lists the WebSocket subprotocols to negotiate with the server.
	CompressionMode      CompressionMode // CompressionMode controls the compression mode.
	CompressionThreshold int             // CompressionThreshold controls the minimum size of a message before compression is applied ,Defaults to 512 bytes for CompressionNoContextTakeover and 128 bytes for CompressionContextTakeover.
	CompressionOptions   *compressionOptions
}

func (obj *Option) Init(client bool) {
	if obj.CompressionOptions != nil {
		if client {
			if obj.CompressionOptions.clientNoContextTakeover {
				obj.CompressionMode = CompressionNoContextTakeover
			} else {
				obj.CompressionMode = CompressionContextTakeover
			}
		} else {
			if obj.CompressionOptions.serverNoContextTakeover {
				obj.CompressionMode = CompressionNoContextTakeover
			} else {
				obj.CompressionMode = CompressionContextTakeover
			}
		}
	} else if obj.CompressionMode == CompressionContextTakeover {
		obj.CompressionOptions = &compressionOptions{
			clientNoContextTakeover: false,
			serverNoContextTakeover: false,
		}
	} else if obj.CompressionMode == CompressionNoContextTakeover {
		obj.CompressionOptions = &compressionOptions{
			clientNoContextTakeover: true,
			serverNoContextTakeover: true,
		}
	}
}
func (obj *Option) Extensions() string {
	if obj.CompressionMode == CompressionDisabled {
		return ""
	}
	extensions := "permessage-deflate"
	if obj.CompressionOptions != nil {
		if obj.CompressionOptions.clientNoContextTakeover {
			extensions += "; client_no_context_takeover"
		}
		if obj.CompressionOptions.serverNoContextTakeover {
			extensions += "; server_no_context_takeover"
		}
	} else if obj.CompressionMode == CompressionNoContextTakeover {
		extensions += "; client_no_context_takeover; server_no_context_takeover"
	}
	return extensions
}

type MessageType = websocket.MessageType
type CompressionMode = websocket.CompressionMode

const (

	// MessageText is for UTF-8 encoded text messages like JSON.
	MessageText websocket.MessageType = websocket.MessageText
	// MessageBinary is for binary messages like protobufs.
	MessageBinary websocket.MessageType = websocket.MessageBinary

	CompressionContextTakeover   CompressionMode = websocket.CompressionContextTakeover
	CompressionDisabled          CompressionMode = websocket.CompressionDisabled
	CompressionNoContextTakeover CompressionMode = websocket.CompressionNoContextTakeover
)

func secWebSocketAccept(secWebSocketKey string) string {
	return tools.Base64Encode(secWebSocketKey)
}
func secWebSocketKey() string {
	b := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, b)
	return tools.Base64Encode(b)
}

func SetClientHeaders(headers http.Header, options ...Option) {
	var option Option
	if len(options) > 0 {
		option = options[0]
	} else {
		option.Init(true)
	}
	if headers.Get("Connection") == "" {
		headers.Set("Connection", "Upgrade")
	}
	if headers.Get("Upgrade") == "" {
		headers.Set("Upgrade", "websocket")
	}
	if headers.Get("Sec-WebSocket-Version") == "" {
		headers.Set("Sec-WebSocket-Version", "13")
	}
	if headers.Get("Sec-WebSocket-Key") == "" {
		headers.Set("Sec-WebSocket-Key", secWebSocketKey())
	}
	if headers.Get("Sec-WebSocket-Protocol") == "" && len(option.Subprotocols) > 0 {
		headers.Set("Sec-WebSocket-Protocol", strings.Join(option.Subprotocols, ","))
	}

	if headers.Get("Sec-WebSocket-Extensions") == "" && option.CompressionMode != CompressionDisabled {
		extensions := "permessage-deflate"
		if option.CompressionOptions != nil {
			if option.CompressionOptions.clientNoContextTakeover {
				extensions += "; client_no_context_takeover"
			}
			if option.CompressionOptions.serverNoContextTakeover {
				extensions += "; server_no_context_takeover"
			}
		} else if option.CompressionMode == CompressionNoContextTakeover {
			extensions += "; client_no_context_takeover; server_no_context_takeover"
		}
		headers.Set("Sec-WebSocket-Extensions", extensions)
	}
}

func GetHeaderOption(header http.Header, client bool) Option {
	var copts *compressionOptions
	for _, extentsions := range header.Values("Sec-WebSocket-Extensions") {
		if strings.Contains(extentsions, "permessage-deflate") {
			if copts == nil {
				copts = new(compressionOptions)
			}
			if strings.Contains(extentsions, "client_no_context_takeover") {
				copts.clientNoContextTakeover = true
			} else if strings.Contains(extentsions, "server_no_context_takeover") {
				copts.serverNoContextTakeover = true
			}
		}
	}
	var model CompressionMode
	if copts == nil {
		model = CompressionDisabled
	} else if client {
		if copts.clientNoContextTakeover {
			model = CompressionNoContextTakeover
		} else {
			model = CompressionContextTakeover
		}
	} else {
		if copts.serverNoContextTakeover {
			model = CompressionNoContextTakeover
		} else {
			model = CompressionContextTakeover
		}
	}
	return Option{
		Subprotocols:       header["Sec-WebSocket-Protocol"],
		CompressionMode:    model,
		CompressionOptions: copts,
	}
}

func NewConn(conn io.ReadWriteCloser, client bool, options ...Option) *Conn {
	var option Option
	if len(options) > 0 {
		option = options[0]
	} else {
		option.Init(client)
	}
	var subprotocol string
	if len(option.Subprotocols) > 0 {
		subprotocol = option.Subprotocols[0]
	}
	return &Conn{
		rwc:    conn,
		option: option,
		conn: newConn(connConfig{
			subprotocol:    subprotocol,
			rwc:            conn,
			client:         client,
			copts:          option.CompressionOptions,
			flateThreshold: option.CompressionThreshold,
			br:             getBufioReader(conn),
			bw:             getBufioWriter(conn),
		}),
	}
}
func NewClientConn(resp *http.Response, options ...Option) (*Conn, error) {
	var option Option
	if len(options) > 0 {
		option = options[0]
		option.Init(true)
	} else {
		option = GetHeaderOption(resp.Header, true)
	}

	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		return nil, fmt.Errorf("response body is not a io.ReadWriteCloser")
	}
	return NewConn(rwc, true, option), nil
}

func NewServerConn(w http.ResponseWriter, r *http.Request, options ...Option) (_ *Conn, err error) {
	var option Option
	if len(options) > 0 {
		option = options[0]
		option.Init(false)
	} else {
		option = GetHeaderOption(r.Header, false)
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
		return nil, errors.New("http.ResponseWriter does not implement http.Hijacker")
	}
	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Sec-WebSocket-Accept", secWebSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
	if extensions := option.Extensions(); extensions != "" {
		w.Header().Set("Sec-WebSocket-Extensions", extensions)
	}
	subproto := selectSubprotocol(r, option.Subprotocols)
	if subproto != "" {
		w.Header().Set("Sec-WebSocket-Protocol", subproto)
	}
	w.WriteHeader(http.StatusSwitchingProtocols)
	// See https://github.com/nhooyr/websocket/issues/166
	if ginWriter, ok := w.(interface {
		WriteHeaderNow()
	}); ok {
		ginWriter.WriteHeaderNow()
	}
	netConn, brw, err := hj.Hijack()
	if err != nil {
		err = fmt.Errorf("failed to hijack connection: %w", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil, err
	}
	// https://github.com/golang/go/issues/32314
	b, _ := brw.Reader.Peek(brw.Reader.Buffered())
	brw.Reader.Reset(io.MultiReader(bytes.NewReader(b), netConn))
	return &Conn{
		rwc:    netConn,
		option: option,
		conn: newConn(connConfig{
			subprotocol:    subproto,
			rwc:            netConn,
			client:         false,
			copts:          option.CompressionOptions,
			flateThreshold: option.CompressionThreshold,
			br:             brw.Reader,
			bw:             brw.Writer,
		}),
	}, nil
}

func (obj *Conn) SetReadLimit(n int64) {
	obj.conn.SetReadLimit(n)
}

func (obj *Conn) Conn() *websocket.Conn {
	return obj.conn
}

func (obj *Conn) Rwc() io.ReadWriteCloser {
	return obj.rwc
}
func (obj *Conn) Option() Option {
	return obj.option
}

func (obj *Conn) RecvJson(ctx context.Context, v any) error {
	if ctx == nil {
		ctx = context.TODO()
	}
	return wsjson.Read(ctx, obj.conn, v)
}
func (obj *Conn) SendJson(ctx context.Context, v any) error {
	if ctx == nil {
		ctx = context.TODO()
	}
	return wsjson.Write(ctx, obj.conn, v)
}
func (obj *Conn) Read(p []byte) (n int, err error) {
	return obj.rwc.Read(p)
}
func (obj *Conn) Write(p []byte) (n int, err error) {
	return obj.rwc.Write(p)
}

func (obj *Conn) Recv(ctx context.Context) (MessageType, []byte, error) {
	if ctx == nil {
		ctx = context.TODO()
	}
	return obj.conn.Read(ctx)
}
func (obj *Conn) Send(ctx context.Context, typ MessageType, p any) error {
	if ctx == nil {
		ctx = context.TODO()
	}
	switch val := p.(type) {
	case []byte:
		return obj.conn.Write(ctx, typ, val)
	case string:
		return obj.conn.Write(ctx, typ, tools.StringToBytes(val))
	default:
		jsonData := tools.Any2json(p)
		if jsonData.IsObject() {
			return obj.conn.Write(ctx, typ, tools.StringToBytes(jsonData.Raw))
		} else {
			return errors.New("类型错误")
		}
	}
}
func (obj *Conn) Close(reasons ...string) error {
	var reason string
	if len(reasons) > 0 {
		reason = reasons[0]
	}
	defer obj.rwc.Close()
	return obj.conn.Close(websocket.StatusInternalError, reason)
}
func (obj *Conn) Ping(ctx context.Context) error {
	if ctx == nil {
		ctx = context.TODO()
	}
	return obj.conn.Ping(ctx)
}
