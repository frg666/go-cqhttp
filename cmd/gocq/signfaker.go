package gocq

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"

	"github.com/Mrs4s/go-cqhttp/internal/base"
	"github.com/Mrs4s/go-cqhttp/internal/download"
)

// 请求 signfaker
func requestSignFaker(method string, url string, headers map[string]string, body io.Reader) ([]byte, error) {
	if !strings.HasPrefix(url, base.SignFaker.URL) {
		url = strings.TrimSuffix(base.SignFaker.URL, "/") + "/" + strings.TrimPrefix(url, "/")
	}
	if headers == nil {
		headers = map[string]string{}
	}
	auth := base.SignFaker.Authorization
	if auth != "-" && auth != "" {
		headers["Authorization"] = auth
	}
	req := download.Request{
		Method: method,
		Header: headers,
		URL:    url,
		Body:   body,
	}.WithTimeout(time.Duration(base.SignFaker.Timeout) * time.Second)
	resp, err := req.Bytes()
	return resp, err
}

// energy 请求
func energySignFaker(uin uint64, id string, _ string, salt []byte) ([]byte, error) {
	url := "custom_energy" + fmt.Sprintf("?data=%v&salt=%v&uin=%v",
		id, hex.EncodeToString(salt), uin)
	response, err := requestSignFaker(http.MethodGet, url, nil, nil)
	if err != nil {
		log.Warnf("获取T544 sign时出现错误: %v. server: %v", err, base.SignFaker.URL)
		return nil, err
	}
	data, err := hex.DecodeString(gjson.GetBytes(response, "data").String())
	if err != nil {
		log.Warnf("获取T544 sign时出现错误: %v. (response data: %v)",
			err, gjson.GetBytes(response, "data").String())
		return nil, err
	}
	if len(data) == 0 {
		log.Warnf("获取T544 sign时出现错误: %v.", "data is empty")
		return nil, errors.New("data is empty")
	}
	return data, nil
}

// sign 请求
func signSignFaker(seq uint64, uin string, cmd string, qua string, buff []byte) (sign []byte, extra []byte, token []byte, err error) {
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	response, err := requestSignFaker(
		http.MethodPost,
		"sign",
		headers,
		bytes.NewReader([]byte(
			fmt.Sprintf("uin=%v&qua=%s&cmd=%s&seq=%v&buffer=%v&qimei36=%v",
				uin, qua, cmd, seq, hex.EncodeToString(buff), device.QImei36))),
	)
	if base.Debug {
		log.Debugf("cmd=%v, qua=%v", cmd, qua)
	}
	if err != nil {
		log.Errorf("请求签名出现错误：%v, server: %v", err, base.SignFaker.URL)
		return nil, nil, nil, err
	}
	sign, _ = hex.DecodeString(gjson.GetBytes(response, "data.sign").String())
	extra, _ = hex.DecodeString(gjson.GetBytes(response, "data.extra").String())
	token, _ = hex.DecodeString(gjson.GetBytes(response, "data.token").String())
	return sign, extra, token, nil
}
