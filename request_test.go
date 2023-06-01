package requests

import (
	"fmt"
	"log"
	"testing"
)

func TestClient(t *testing.T) {
	resp, err := Get("https://ascii2d.net/")
	if err != nil {
		log.Panic(err)
	}
	resp.Response()
	fmt.Println(resp.Text())
}
