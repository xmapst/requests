package tools

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/png"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/andybalholm/brotli"
	jsoniter "github.com/json-iterator/go"
	"github.com/tidwall/gjson"
	_ "golang.org/x/image/webp"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding/simplifiedchinese"
)

var JsonConfig = jsoniter.Config{
	EscapeHTML:    true,
	CaseSensitive: true,
}.Froze()

// CharSet 网页解码，并返回 编码
func CharSet(content []byte, contentType string) ([]byte, string, error) {
	chSet, chSetName, _ := charset.DetermineEncoding(content, contentType)
	chSetContent, err := chSet.NewDecoder().Bytes(content)
	return chSetContent, chSetName, err
}

// Decode 转码
func Decode[T string | []byte](txt T, code string) T {
	var result any
	switch val := (any)(txt).(type) {
	case string:
		switch code {
		case "gb2312":
			result, _ = simplifiedchinese.HZGB2312.NewDecoder().String(val)
		case "gbk":
			result, _ = simplifiedchinese.GBK.NewDecoder().String(val)
		default:
			result = val
		}
	case []byte:
		switch code {
		case "gb2312":
			result, _ = simplifiedchinese.HZGB2312.NewDecoder().Bytes(val)
		case "gbk":
			result, _ = simplifiedchinese.GBK.NewDecoder().Bytes(val)
		default:
			result = val
		}
	}
	return result.(T)
}

// DecodeRead 转码
func DecodeRead(txt io.Reader, code string) io.Reader {
	switch code {
	case "gb2312":
		txt = simplifiedchinese.HZGB2312.NewDecoder().Reader(txt)
	case "gbk":
		txt = simplifiedchinese.GBK.NewDecoder().Reader(txt)
	}
	return txt
}

// Any2json 转成json
func Any2json(data any, path ...string) gjson.Result {
	var result gjson.Result
	switch value := data.(type) {
	case []byte:
		if len(path) == 0 {
			result = gjson.ParseBytes(value)
		} else {
			result = gjson.GetBytes(value, path[0])
		}
	case string:
		if len(path) == 0 {
			result = gjson.Parse(value)
		} else {
			result = gjson.Get(value, path[0])
		}
	default:
		marStr, _ := JsonConfig.MarshalToString(value)
		if len(path) == 0 {
			result = gjson.Parse(marStr)
		} else {
			result = gjson.Get(marStr, path[0])
		}
	}
	return result
}

// Any2struct 转成struct
func Any2struct(data any, stru any) error {
	con, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(con, stru)
}

// Merge 合并两个结构体 *ci c2
func Merge(c1 any, c2 any) {
	v2 := reflect.ValueOf(c2)             // 初始化为c2保管的具体值的v2
	v1_elem := reflect.ValueOf(c1).Elem() // 返回 c1 指针保管的值
	for i := 0; i < v2.NumField(); i++ {
		field2 := v2.Field(i)                                                                                             // 返回结构体的第i个字段
		if !reflect.DeepEqual(field2.Interface(), reflect.Zero(field2.Type()).Interface()) && v1_elem.Field(i).CanSet() { // 如果第二个构造体 这个字段不为空
			v1_elem.Field(i).Set(field2) // 设置值
		}
	}
}

// Base64Encode base64 加密
func Base64Encode[T string | []byte](val T) string {
	switch con := (any)(val).(type) {
	case string:
		return base64.StdEncoding.EncodeToString(StringToBytes(con))
	case []byte:
		return base64.StdEncoding.EncodeToString(con)
	}
	return ""
}

// Base64Decode base64解密
func Base64Decode(val string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(val)
}

// ZipDecode 压缩解码
func ZipDecode(ctx context.Context, r *bytes.Buffer, encoding string) (*bytes.Buffer, error) {
	rs := bytes.NewBuffer(nil)
	var err error
	if encoding == "br" {
		err = CopyWitchContext(ctx, rs, brotli.NewReader(r))
		return rs, err
	}
	var reader io.ReadCloser
	switch encoding {
	case "deflate":
		reader = flate.NewReader(r)
	case "gzip":
		if reader, err = gzip.NewReader(r); err != nil {
			return r, err
		}
	default:
		return r, err
	}
	defer func() {
		if reader != nil {
			reader.Close()
		}
	}()
	err = CopyWitchContext(ctx, rs, reader)
	return rs, err
}

// BytesToString 字节串转字符串
func BytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return string(b)
}

// StringToBytes 字符串转字节串
func StringToBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func WrapError(err error, val ...any) error {
	return fmt.Errorf("%w,%s", err, fmt.Sprint(val...))
}

func CopyWitchContext(ctx context.Context, writer io.Writer, reader io.Reader) (err error) {
	p := make(chan struct{})
	go func() {
		defer func() {
			if recErr := recover(); recErr != nil && err == nil {
				err = errors.New(fmt.Sprint(recErr))
			}
			close(p)
		}()
		_, err = io.Copy(writer, reader)
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = nil
		}
	}()
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-p:
	}
	return
}

func ParseHost(host string) (net.IP, int) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, 4
		} else if ip6 := ip.To16(); ip6 != nil {
			return ip6, 6
		}
	}
	return nil, 0
}

func ParseIp(ip net.IP) int {
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return 4
		} else if ip6 := ip.To16(); ip6 != nil {
			return 6
		}
	}
	return 0
}

func SplitHostPort(address string) (string, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	portnum, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}
	if 1 > portnum || portnum > 0xffff {
		return "", 0, errors.New("port number out of range " + port)
	}
	return host, portnum, nil
}

func GetServerName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func GetContentTypeWithBytes(content []byte) string {
	return http.DetectContentType(content)
}

func ImgDiffer(c, c2 []byte) (float64, error) {
	img1, _, err := image.Decode(bytes.NewBuffer(c))
	if err != nil {
		return 0, err
	}
	img2, _, err := image.Decode(bytes.NewBuffer(c2))
	if err != nil {
		return 0, err
	}
	var score float64
	bounds := img1.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r1, g1, b1, _ := img1.At(x, y).RGBA()
			r2, g2, b2, _ := img2.At(x, y).RGBA()
			score += math.Pow(float64(r1)-float64(r2), 2)
			score += math.Pow(float64(g1)-float64(g2), 2)
			score += math.Pow(float64(b1)-float64(b2), 2)
		}
	}
	score /= math.Pow(2, 16) * math.Pow(float64(bounds.Dx()), 2) * math.Pow(float64(bounds.Dy()), 2)
	return score, nil
}

func Signal(preCtx context.Context, fun func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGILL, syscall.SIGTRAP,
		syscall.SIGABRT, syscall.SIGBUS, syscall.SIGFPE, syscall.SIGKILL, syscall.SIGSEGV, syscall.SIGPIPE,
		syscall.SIGALRM, syscall.SIGTERM)
	select {
	case <-preCtx.Done():
		if fun != nil {
			fun()
		}
		signal.Stop(ch)
	case s := <-ch:
		if fun != nil {
			fun()
		}
		signal.Stop(ch)
		signal.Reset(s)
		if p, err := os.FindProcess(os.Getpid()); err == nil && p != nil {
			sg, ok := s.(syscall.Signal)
			if ok && sg == syscall.SIGINT {
				p.Signal(syscall.SIGKILL)
			} else {
				p.Signal(s)
			}
		}
	}
}

func SetUnExportedField[T any](source T, fieldName string, newFieldVal any) T {
	v := reflect.ValueOf(source)
	vptr := reflect.New(v.Type()).Elem()
	vptr.Set(v)
	tv := vptr.FieldByName(fieldName)
	tv = reflect.NewAt(tv.Type(), unsafe.Pointer(tv.UnsafeAddr())).Elem()
	tv.Set(reflect.ValueOf(newFieldVal))
	return vptr.Interface().(T)
}
