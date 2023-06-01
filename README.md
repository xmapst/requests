# requests
ja3指纹,http2 指纹,主流代理协议,类型自动转换,覆盖python requests 所有的功能

# 功能概述

- 基于net/http 二次封装
- cookies 开关，连接池开关，http2，ja3
- 自实现socks五,http代理,https代理
- 自动解压缩,解码
- dns缓存
- 类型自动转化
- 尝试重试，请求回调

# 发送http请求

```golang
package main

import (
    "log"

    "github.com/xmapst/requests"
)

func main() {
    reqCli, err := requests.NewClient() //创建请求客户端
    if err != nil {
        log.Panic(err)
    }
    response, err := reqCli.Get("http://myip.top") //发送get请求
    if err != nil {
        log.Panic(err)
    }
    log.Print(response.Text())    //获取内容,解析为字符串
    log.Print(response.Content()) //获取内容,解析为字节
    log.Print(response.Json())    //获取json,解析为gjson
    log.Print(response.Html())    //获取内容,解析为html
    log.Print(response.Cookies()) //获取cookies
}

```

# 发送websocket 请求

```golang
package main

import (
	"context"
	"log"

	"github.com/xmapst/requests"
	"github.com/xmapst/requests/websocket"
)

func main() {
	reqCli, err := requests.NewClient() //创建请求客户端
	if err != nil {
		log.Panic(err)
	}
	response, err := reqCli.Get("ws://82.157.123.54:9010/ajaxchattest", requests.RequestOption{Headers: map[string]string{
		"Origin": "http://coolaf.com",
	}}) //发送websocket请求
	if err != nil {
		log.Panic(err)
	}
	defer response.Close()
	wsCli := response.WebSocket()
	if err = wsCli.Send(context.TODO(), websocket.MessageText, []byte("测试")); err != nil { //发送txt 消息
		log.Panic(err)
	}
	msgType, con, err := wsCli.Recv(context.TODO()) //接收消息
	if err != nil {
		log.Panic(err)
	}
	log.Print(msgType)     //消息类型
	log.Print(string(con)) //消息内容
}
```
# ipv4,ipv6 地址控制解析
```go
func main() {
	reqCli, err := requests.NewClient(requests.ClientOption{
		AddrType: requests.Ipv4, //优先解析ipv4地址
		// AddrType: requests.Ipv6,//优先解析ipv6地址
	})
	if err != nil {
		log.Panic(err)
	}
	href := "https://test.ipw.cn"
	resp, err := reqCli.Get(href)
	if err != nil {
		log.Panic(err)
	}
	log.Print(resp.Text())
	log.Print(resp.StatusCode())
}
``` 
# ja3 伪造指纹
## 根据字符串生成指纹
```go
func main() {
	reqCli, err := requests.NewClient()
	if err != nil {
		log.Panic(err)
	}
	ja3Str := "772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
	Ja3Spec, err := ja3.CreateSpecWithStr(ja3Str)//根据字符串生成指纹
	if err != nil {
		log.Panic(err)
	}
	response, err := reqCli.Get("https://tools.scrapfly.io/api/fp/ja3?extended=1", requests.RequestOption{Ja3Spec: Ja3Spec})
	if err != nil {
		log.Panic(err)
	}
	log.Print(response.Json().Get("ja3").String())
	log.Print(response.Json().Get("ja3").String() == ja3Str)
}
```
## 根据id 生成指纹
```go
func main() {
	reqCli, err := requests.NewClient()
	if err != nil {
		log.Panic(err)
	}
	Ja3Spec, err := ja3.CreateSpecWithId(ja3.HelloChrome_Auto)//根据id 生成指纹
	if err != nil {
		log.Panic(err)
	}
	response, err := reqCli.Get("https://tools.scrapfly.io/api/fp/ja3?extended=1", requests.RequestOption{Ja3Spec: Ja3Spec})
	if err != nil {
		log.Panic(err)
	}
	log.Print(response.Json().Get("ja3").String())
}
```
## ja3 开关
```go
func main() {
	reqCli, err := requests.NewClient()
	if err != nil {
		log.Panic(err)
	}
	response, err := reqCli.Get("https://tools.scrapfly.io/api/fp/ja3?extended=1", requests.RequestOption{Ja3: true})//使用最新chrome 指纹
	if err != nil {
		log.Panic(err)
	}
	log.Print(response.Json().Get("ja3").String())
}
```
## h2 指纹开关
```go
func main() {
	reqCli, err := requests.NewClient(requests.ClientOption{
		H2Ja3: true,
	})
	if err != nil {
		log.Panic(err)
	}
	href := "https://tools.scrapfly.io/api/fp/anything"
	resp, err := reqCli.Get(href)
	if err != nil {
		log.Panic(err)
	}
	log.Print(resp.Text())
}
```
## 修改h2指纹
```go
func main() {
	reqCli, err := requests.NewClient(requests.ClientOption{
		H2Ja3Spec: ja3.H2Ja3Spec{
			InitialSetting: []ja3.Setting{
				{Id: 1, Val: 65555},
				{Id: 2, Val: 1},
				{Id: 3, Val: 2000},
				{Id: 4, Val: 6291457},
				{Id: 6, Val: 262145},
			},
			ConnFlow: 15663106,
			OrderHeaders: []string{
				":method",
				":path",
				":scheme",
				":authority",
			},
		},
	})
	if err != nil {
		log.Panic(err)
	}
	href := "https://tools.scrapfly.io/api/fp/anything"
	resp, err := reqCli.Get(href)
	if err != nil {
		log.Panic(err)
	}
	log.Print(resp.Text())
}
```
## 采集全国公共资源网和中国政府采购网的列表页的标题
```go
package main
import (
	"log"
	
	"github.com/xmapst/requests"
)
func main() {
	reqCli, err := requests.NewClient()
	if err != nil {
		log.Panic(err)
	}
	resp, err := reqCli.Get("http://www.ccgp.gov.cn/cggg/zygg/")
	if err != nil {
		log.Panic(err)
	}
	html := resp.Html()
	lis := html.Finds("ul.c_list_bid li")
	for _, li := range lis {
		title := li.Find("a").Get("title")
		log.Print(title)
	}
	resp, err = reqCli.GET("http://deal.ggzy.gov.cn/ds/deal/dealList_find.jsp", requests.RequestOption{
		Data: map[string]string{
			"TIMEBEGIN_SHOW": "2023-04-26",
			"TIMEEND_SHOW":   "2023-05-05",
			"TIMEBEGIN":      "2023-04-26",
			"TIMEEND":        "2023-05-05",
			"SOURCE_TYPE":    "1",
			"DEAL_TIME":      "02",
			"DEAL_CLASSIFY":  "01",
			"DEAL_STAGE":     "0100",
			"DEAL_PROVINCE":  "0",
			"DEAL_CITY":      "0",
			"DEAL_PLATFORM":  "0",
			"BID_PLATFORM":   "0",
			"DEAL_TRADE":     "0",
			"isShowAll":      "1",
			"PAGENUMBER":     "2",
			"FINDTXT":        "",
		},
	})
	if err != nil {
		log.Panic(err)
	}
	jsonData := resp.Json()
	lls := jsonData.Get("data").Array()
	for _, ll := range lls {
		log.Print(ll.Get("title"))
	}
}
```