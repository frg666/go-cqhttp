package gocq

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/RomiChan/websocket"
	"github.com/pkg/errors"
	"github.com/segmentio/asm/base64"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"

	"github.com/Mrs4s/MiraiGo/utils"

	"github.com/Mrs4s/go-cqhttp/internal/base"
	"github.com/Mrs4s/go-cqhttp/internal/download"
)

var vivo50Server = "http://localhost:8888"     // 服务端地址，去除了后缀 /
var serverIdentityKey = "kfccrazytuesdayvme50" // RPC 服务端身份密钥，用于客户端确认服务端身份。
var authKey = "kfcvme50"                       // RPC 客户端验证密钥，用于服务端确认客户端身份。

var vivo50Token = "" // 握手成功后返回的 token , 经过base64解码

// Vivo50SecKeys 保存密钥信息
type Vivo50SecKeys struct {
	AESKey          []byte
	PrivateKeyBytes []byte
	PublicKeyBytes  []byte
	PrivateKey      *rsa.PrivateKey
	PublicKey       *rsa.PublicKey
}

// 保存生成的密钥信息
var vivo50SecKeys Vivo50SecKeys

func initVivo50Config() {
	if base.Account.Vivo50SignServer == nil {
		log.Warn(`缺少 vivo50 签名服务配置，使用默认配置
vivo50Server = "http://localhost:8888"      
serverIdentityKey = "kfccrazythusdayvivo50" 
authKey = "kfc"  
		`)
		return
	}
	kfcServer := base.Account.Vivo50SignServer.KfcServer
	identityKey := base.Account.Vivo50SignServer.ServerIdentityKey
	aKey := base.Account.Vivo50SignServer.AuthKey
	if len(kfcServer) > 2 {
		vivo50Server = kfcServer
	}
	if len(identityKey) > 0 {
		serverIdentityKey = identityKey
	}
	if len(aKey) > 0 {
		authKey = aKey
	}
	vivo50Server = strings.TrimSuffix(vivo50Server, "/")
	log.Infof(`vivo50 签名服务配置
vivo50Server = %v     
serverIdentityKey = "%v" 
authKey = "%v"  
		`, vivo50Server, serverIdentityKey, authKey)
}

func saveFile(filename string, content []byte) {
	f, err := os.Create(filename)
	if err != nil {
		log.Warnf("创建文件 %v 失败，%v", filename, err)
	}
	defer f.Close()

	_, err = f.Write(content)
	if err != nil {
		log.Warnf("写入文件 %v 失败，%v", filename, err)
	}
}

func readFile(filename string) ([]byte, error) {
	fileHandle, err := os.Open(filename)
	if err != nil {
		log.Warnf("打开文件 %v 失败：%v", filename, err)
		return nil, err
	}
	defer fileHandle.Close()

	fileInfo, err := fileHandle.Stat()
	if err != nil {
		log.Warnf("获取文件 %v 信息失败：%v", filename, err)
		return nil, err
	}

	b := make([]byte, fileInfo.Size())
	_, err = fileHandle.Read(b)
	if err != nil {
		log.Warnf("读取文件 %v 失败：%v", filename, err)
		return nil, err
	}
	return b, nil
}

// 保存生成的密钥信息
func saveSecInfo(aesKey []byte, rsaPrivateKey []byte, rsaPublicKey []byte) {
	saveFile("vivo50_aes.key", aesKey)
	saveFile("vivo50_rsa.key", rsaPrivateKey)
	saveFile("vivo50_rsa_pub.key", rsaPublicKey)
}

// 读取上次生成的密钥信息
func loadSecInfo(aesFile string, rsaPrivateFile string, rsaPublicFile string) (
	aesKey []byte, rsaPrivateKey []byte, rsaPublicKey []byte, err error) {
	aesKey, err = readFile(aesFile)
	if err != nil {
		log.Warn("读取 AES key 文件失败")
		return nil, nil, nil, err
	}
	rsaPrivateKey, err = readFile(rsaPrivateFile)
	if err != nil {
		log.Warn("读取 rsa private key 文件失败")
		return nil, nil, nil, err
	}
	rsaPublicKey, err = readFile(rsaPublicFile)
	if err != nil {
		log.Warn("读取 rsa public key 文件失败")
		return nil, nil, nil, err
	}
	// 验证读取的密钥
	if len(aesKey) != 16 {
		log.Warnf("错误的 AES KEY 长度 %v", len(aesKey))
		return nil, nil, nil, errors.New("wrong aes length")
	}
	priK, err1 := parsePrivateKey(rsaPrivateKey)
	pubK, err2 := parsePublicKey(string(rsaPublicKey))
	if err1 != nil || err2 != nil {
		log.Warn("解析密钥出错")
		return nil, nil, nil, errors.New("parse rsa key failed")
	}
	if !priK.PublicKey.Equal(pubK) {
		log.Warn("读取到不匹配的 RSA 密钥，将重新生成")
		return nil, nil, nil, err
	}
	vivo50SecKeys = Vivo50SecKeys{
		AESKey:          aesKey,
		PrivateKeyBytes: rsaPrivateKey,
		PublicKeyBytes:  rsaPublicKey,
		PrivateKey:      priK,
		PublicKey:       pubK,
	}
	return aesKey, rsaPrivateKey, rsaPublicKey, nil
}

// requestVivo50HttpAPI 向 vivo50 服务端发送 HTTP 请求, url 为路由
func requestVivo50HttpAPI(method string, url string, headers map[string]string, body io.Reader) (string, []byte, error) {
	server := vivo50Server
	if headers == nil {
		headers = map[string]string{}
	}
	url = server + url
	req := download.Request{
		Method: method,
		Header: headers,
		URL:    url,
		Body:   body,
	}.WithTimeout(time.Duration(base.SignServerTimeout) * time.Second) // 共用 qsign 超时时间设置
	resp, err := req.Bytes()
	return server, resp, err
}

// checkVivo50Server 请求并验证 vivo50 签名服务端信息和身份，返回 publicKey 会话超时时间 和 错误信息
func checkVivo50Server() (publicKey string, timeout int64, e error) {
	server, resp, err := requestVivo50HttpAPI(
		http.MethodGet,
		"/service/rpc/handshake/config",
		nil, nil,
	)
	if err != nil {
		log.Errorf("获取 RPC 信息出错: %v，server: %v 。请检查签名服务可用性", err, server)
		return "", 0, err
	}
	publicKey, timeout, keySignature :=
		gjson.GetBytes(resp, "publicKey").String(),
		gjson.GetBytes(resp, "timeout").Int(),
		gjson.GetBytes(resp, "keySignature").String()
	pKeyRsaSha1 := sha1.Sum(
		[]byte(
			serverIdentityKey + publicKey))
	clientKeySignatureBytes := sha1.Sum(
		[]byte(
			hex.EncodeToString(pKeyRsaSha1[:]) + serverIdentityKey))
	if hex.EncodeToString(clientKeySignatureBytes[:]) == keySignature {
		return publicKey, timeout, nil
	}
	return "", 0, errors.New("client calculated key signature doesn't match the server provides")
}

// generateSecInfo 生成一个 16-byte AES 密钥和 4096-bit RSA 密钥对
func generateSecInfo() (aesKey []byte, rsaPrivateKey []byte, rsaPublicKey []byte, err error) {
	aesKey, rsaPrivateKey, rsaPublicKey, err =
		loadSecInfo("vivo50_aes.key", "vivo50_rsa.key", "vivo50_rsa_pub.key")
	if err == nil {
		return aesKey, rsaPrivateKey, rsaPublicKey, nil
	}
	aesKey = make([]byte, 16)
	_, err = rand.Read(aesKey)
	if err != nil {
		return nil, []byte{}, []byte{}, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return aesKey, []byte{}, []byte{}, err
	}
	publicKey := &privateKey.PublicKey

	// Serialize key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}

	// Convert private key to bytes
	rsaPrivateKey = pem.EncodeToMemory(privateKeyPEM)
	rsaPublicKey = pem.EncodeToMemory(publicKeyPEM)
	vivo50SecKeys = Vivo50SecKeys{
		AESKey:          aesKey,
		PrivateKeyBytes: rsaPrivateKey,
		PublicKeyBytes:  rsaPublicKey,
		PrivateKey:      privateKey,
		PublicKey:       publicKey,
	}
	saveSecInfo(aesKey, rsaPrivateKey, rsaPublicKey) // 保存以便下次读取
	return aesKey, rsaPrivateKey, rsaPublicKey, err
}

// HandshakeRequest 握手请求
type HandshakeRequest struct {
	ClientRsa string `json:"clientRsa"`
	Secret    string `json:"secret"`
}

// HandshakeInfo Secret 内容结构
type HandshakeInfo struct {
	AuthorizationKey string `json:"authorizationKey"`
	SharedKey        string `json:"sharedKey"`
	Botid            int64  `json:"botid"`
}

func parsePublicKey(publicKeyString string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyString))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func parsePrivateKey(privateKeyBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// handshake 与服务端进行握手
func handshake() bool {
	publicKey, timeout, err := checkVivo50Server()
	if err != nil {
		log.Errorf("检验签名服务信息出错: %v ", err)
		return false
	}
	log.Infof("验证服务端身份成功，会话超时时间：%v", timeout)

	aesKey, _, rsaPub, err := generateSecInfo()
	if err != nil {
		log.Errorf("生成密钥出错：%v, 无法与服务端建立连接", err)
		return false
	}

	handshakeInfo := HandshakeInfo{
		AuthorizationKey: authKey,
		SharedKey:        string(aesKey),
		Botid:            cli.Uin,
	}

	// 将握手信息序列化为JSON字符串
	infoBytes, err := json.Marshal(handshakeInfo)
	if err != nil {
		log.Errorf("序列化握手信息json出错")
		return false
	}

	// 使用最初服务端返回的公钥加密握手信息
	publicKey = "-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----"
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		log.Warn("failed to decode PEM block")
		return false
	}
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Errorf("parse publicKey failed: %v. publicKey is\n%v", err, publicKey)
		return false
	}
	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, pk.(*rsa.PublicKey), infoBytes)
	if err != nil {
		log.Errorf("rsa.EncryptPKCS1v15 error: %v", err)
		return false
	}
	hr := HandshakeRequest{
		ClientRsa: base64.StdEncoding.EncodeToString(rsaPub),
		Secret:    hex.EncodeToString(cipher),
	}
	body, err := json.Marshal(hr)
	if err != nil {
		log.Errorf("parse request body failed: %v.", err)
		return false
	}

	headers := map[string]string{"Content-Type": "application/json"}
	server, resp, err := requestVivo50HttpAPI(
		http.MethodPost,
		"/service/rpc/handshake/handshake",
		headers,
		bytes.NewReader(body),
	)
	if err != nil {
		log.Errorf("与服务端 %v 握手请求失败：%v", server, err)
		return false
	}
	status := gjson.GetBytes(resp, "status").Int()
	if status != 200 {
		log.Errorf("与服务端 %v 握手失败：%v", server, gjson.GetBytes(resp, "reason").String())
		return false
	}
	b, _ := base64.StdEncoding.DecodeString(gjson.GetBytes(resp, "token").String())
	vivo50Token = utils.B2S(b)
	log.Info("握手成功")
	return true
}

func signTimestamp() (string, string, error) {
	currentMill := time.Now().UnixMilli()
	timeString := strconv.FormatInt(currentMill, 10)
	hash := sha256.Sum256([]byte(timeString))

	signature, err := rsa.SignPKCS1v15(rand.Reader, vivo50SecKeys.PrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", "", err
	}
	// 对签名进行 Base64 编码
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	return timeString, signatureBase64, nil
}

func getHeader() map[string]string {
	headers := map[string]string{}
	t, st, err := signTimestamp()
	if err != nil {
		log.Warnf("签名时间戳出错 %v", err)
	}
	headers["Authorization"] = vivo50Token
	headers["X-SEC-time"] = t
	headers["X-SEC-Signature"] = st
	return headers
}

// getSessionResponse 操作会话响应码，204为正常，403为headers出错，404为会话不存在，-1为请求出错
func getSessionResponse(method string, action string) int {
	server := strings.TrimSuffix(vivo50Server, "/")
	url := server + action
	req := download.Request{
		Method: http.MethodGet,
		Header: getHeader(),
		URL:    url,
	}.WithTimeout(time.Duration(base.SignServerTimeout) * time.Second)
	r, e := req.Response()
	code := r.StatusCode
	_ = r.Body.Close()
	if e != nil {
		log.Warnf("请求 %v %v 出错: %v", method, url, e)
		return -1
	}

	return code
}

// checkSession 检查会话状态，204 正常
func checkVivo50Session() int {
	return getSessionResponse(http.MethodGet, "/service/rpc/session/check")
}

// closeSession 关闭会话，204 成功
func closeVivo50Session() int {
	return getSessionResponse(http.MethodDelete, "/service/rpc/session")
}

var aesCipherBlock cipher.Block

func aesEncrypt(content []byte) ([]byte, error) {
	if aesCipherBlock == nil {
		block, err := aes.NewCipher(vivo50SecKeys.AESKey)
		if err != nil {
			log.Error("get cipher block failed")
			return nil, err
		}
		aesCipherBlock = block
	}
	ciphertext := make([]byte, aes.BlockSize+len(content))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(aesCipherBlock, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], content)
	return ciphertext, nil
}

func aesDecrypt(ciphertext []byte) ([]byte, error) {
	if aesCipherBlock == nil {
		block, err := aes.NewCipher(vivo50SecKeys.AESKey)
		if err != nil {
			log.Error("get cipher failed")
			return nil, err
		}
		aesCipherBlock = block
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext is too short (< 16)")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(aesCipherBlock, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

var vivo50WSConnect *websocket.Conn
var channels = map[string]chan []byte{
	"send": make(chan []byte, 5),
	"init": make(chan []byte, 1),
	"sign": make(chan []byte, 5),
	"tlv":  make(chan []byte, 5),
}

func connectVivo50WebSocket() {
	i := 0
	for {
		i++
		if !handshake() {
			log.Warn("与 vivo50 签名服务器握手失败，正在重试，请确认服务可用")
			time.Sleep(3 * time.Second)
			if i == 3 {
				log.Error("无法与签名服务器成功握手")
				os.Exit(0)
			}
		} else {
			break
		}
	}

	headers := http.Header{}
	for k, v := range getHeader() {
		headers.Add(k, v)
	}
	c, r, err := websocket.DefaultDialer.Dial(vivo50Server+"/service/rpc/session", headers)
	_ = r.Body.Close()
	if err != nil {
		log.Fatalf("连接 vivo50 ws 服务出错：%v", err)
	}
	vivo50WSConnect = c
	log.Infof("连接 vivo50 ws 服务成功")
	vivo50InitSignService() // 初始化签名服务

	sessionInterrupt := make(chan int, 1)
	osInterrupt := make(chan os.Signal, 1)
	signal.Notify(osInterrupt, os.Interrupt)
	go func() {
		for {
			_, data, err := vivo50WSConnect.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Warn("与 vivo50 签名服务器的 websocket 连接断开")
					sessionInterrupt <- 1
					connectVivo50WebSocket()
					return
				}
				log.Warnf("读取信息出错 %v. server: %v", err, vivo50Server)
			}
			resp, err := aesDecrypt(data)
			if err != nil {
				log.Warnf("解密信息出错 %v. server: %v", err, vivo50Server)
			}
			switch gjson.GetBytes(resp, "packetType").String() {
			case "service.interrupt":
				log.Warn("会话过期，重新建立连接中")
				sessionInterrupt <- 1
				connectVivo50WebSocket()
				return
			case "service.error":
				log.Warnf("出现错误: %v", gjson.GetBytes(resp, "message").String())

			case "rpc.initialize":
				channels["init"] <- resp

			case "rpc.service.send":
				channels["send"] <- resp

			case "rpc.sign":
				channels["sign"] <- resp

			case "rpc.tlv":
				channels["tlv"] <- resp
			}
		}
	}()
	go func() {
		for {
			select {
			case resp := <-channels["send"]:
				sendPacket(resp)
			case <-sessionInterrupt:
				return
			case <-osInterrupt:
				code := closeVivo50Session()
				if code != 204 {
					log.Warnf("关闭连接出错：%v", code)
					return
				}
				return
			}
		}
	}()
}

func vivo50InitSignService() {
	initPacket := Vivo50Packet{
		PacketID:   "0",
		PacketType: "service.initialize",
		ExtArgs: ExtArgs{
			KeyQimei36: cli.Device().QImei36,
			BotProtocol: BotProtocol{
				ProtocolValue: ProtocolValue{
					Ver: "8.9.58",
				},
			},
		},
		Device: Vivo50Device{
			Display:     string(cli.Device().Display),
			Product:     string(cli.Device().Product),
			Device:      string(cli.Device().Device),
			Board:       string(cli.Device().Board),
			Brand:       string(cli.Device().Brand),
			Model:       string(cli.Device().Model),
			Bootloader:  string(cli.Device().Bootloader),
			Fingerprint: string(cli.Device().FingerPrint),
			BootID:      string(cli.Device().BootId),
			ProcVersion: string(cli.Device().ProcVersion),
			BaseBand:    string(cli.Device().BaseBand),
			Version: Vivo50Version{
				Incremental: string(cli.Device().Version.Incremental),
				Release:     string(cli.Device().Version.Release),
				Codename:    string(cli.Device().Version.CodeName),
				Sdk:         int(cli.Device().Version.SDK),
			},
			SimInfo:    string(cli.Device().SimInfo),
			OsType:     string(cli.Device().OSType),
			MacAddress: string(cli.Device().MacAddress),
			WifiBSSID:  string(cli.Device().WifiBSSID),
			WifiSSID:   string(cli.Device().WifiSSID),
			ImsiMd5:    string(cli.Device().IMSIMd5),
			Imei:       cli.Device().IMEI,
			Apn:        string(cli.Device().APN),
			AndroidID:  string(cli.Device().AndroidId),
			GUID:       string(cli.Device().Guid),
		},
	}
	sendWSMessage(&initPacket)
	resp := <-channels["init"]
	if gjson.GetBytes(resp, "packetType").String() == "rpc.initialize" {
		log.Info(" vivo50 签名服务成初始化功")
	}
}

// sendWSMessage 向 vivo50 签名服务器发送 ws 数据
func sendWSMessage(packet *Vivo50Packet) {
	d, _ := json.Marshal(packet)
	d, e := aesEncrypt(d)
	if e != nil {
		log.Warnf("aes encrypt error: %v", e)
	}
	e = vivo50WSConnect.WriteMessage(websocket.BinaryMessage, d)
	if e != nil {
		log.Warnf("vivo50: send ws msg error: %v", e)
	}
}

// sendPacket 接收到 rpc.service.send 后发送返回包
func sendPacket(resp []byte) {
	packetID := gjson.GetBytes(resp, "packetId").String()
	cmd := gjson.GetBytes(resp, "command").String()
	data, _ := hex.DecodeString(gjson.GetBytes(resp, "data").String())
	r, e := cli.SendSsoPacket(cmd, data)
	if e != nil {
		log.Warnf("get sendSsoPacket response failed: %v", e)
		return
	}
	pac := Vivo50Packet{
		PacketID:   packetID,
		PacketType: "rpc.service.send",
		Command:    cmd,
		Data:       hex.EncodeToString(r),
	}
	sendWSMessage(&pac)
}

func vivo50Energy(_ uint64, id string, _ string, _ []byte) ([]byte, error) {
	if code := checkVivo50Session(); code != 204 {
		log.Warnf("vivo50 session error: %v", code)
		_ = vivo50WSConnect.Close()
		return nil, errors.New("session error")
	}
	pac := Vivo50Packet{
		PacketID:   strconv.FormatInt(time.Now().UnixMilli(), 10),
		PacketType: "rpc.tlv",
		TlvType:    0x544,
		ExtArgs: ExtArgs{
			KeyCommandStr: "810_a",
		},
		Content: id,
	}
	sendWSMessage(&pac)
	resp := <-channels["tlv"]
	data, err := hex.DecodeString(gjson.GetBytes(resp, "response").String())
	if err != nil {
		log.Warnf("获取T544 sign时出现错误: %v", err)
		return nil, err
	}
	if len(data) == 0 {
		log.Warnf("获取T544 sign时出现错误: %v.", "data is empty")
		return nil, errors.New("data is empty")
	}
	return data, nil
}

func vivo50Sign(seq uint64, _ string, cmd string, _ string, buff []byte) (
	sign []byte, extra []byte, token []byte, err error) {
	if code := checkVivo50Session(); code != 204 {
		log.Warnf("vivo50 session error: %v", code)
		_ = vivo50WSConnect.Close()
		return nil, nil, nil, errors.New("session error")
	}
	pac := Vivo50Packet{
		PacketID:   strconv.FormatInt(time.Now().UnixMilli(), 10),
		PacketType: "rpc.sign",
		SeqID:      seq,
		Command:    cmd,
		ExtArgs:    ExtArgs{},
		Content:    hex.EncodeToString(buff),
	}
	sendWSMessage(&pac)
	resp := <-channels["sign"]
	sign, _ = hex.DecodeString(gjson.GetBytes(resp, "response.sign").String())
	extra, _ = hex.DecodeString(gjson.GetBytes(resp, "response.extra").String())
	token, _ = hex.DecodeString(gjson.GetBytes(resp, "response.token").String())

	return sign, extra, token, nil
}

// Vivo50Packet ws 请求包
type Vivo50Packet struct {
	PacketID   string `json:"packetId"`
	PacketType string `json:"packetType"`

	Message string  `json:"message"`
	ExtArgs ExtArgs `json:"extArgs"`

	SeqID   uint64 `json:"seqId"`
	Command string `json:"command"`
	Content string `json:"content"`
	TlvType int    `json:"tlvType"`

	Data string `json:"data"`

	Device Vivo50Device `json:"device"`
}

// ExtArgs extArgs 结构
type ExtArgs struct {
	KeyQimei36    string      `json:"KEY_QIMEI36"`
	BotProtocol   BotProtocol `json:"BOT_PROTOCOL"`
	KeyCommandStr string      `json:"KEY_COMMAND_STR"`
}

// BotProtocol Bot 协议信息
type BotProtocol struct {
	ProtocolValue ProtocolValue `json:"protocolValue"`
}

// ProtocolValue 协议值 8.9.58
type ProtocolValue struct {
	Ver string `json:"ver"`
}

// Vivo50Device 设备信息
type Vivo50Device struct {
	Display     string        `json:"display"`
	Product     string        `json:"product"`
	Device      string        `json:"device"`
	Board       string        `json:"board"`
	Brand       string        `json:"brand"`
	Model       string        `json:"model"`
	Bootloader  string        `json:"bootloader"`
	Fingerprint string        `json:"fingerprint"`
	BootID      string        `json:"bootId"`
	ProcVersion string        `json:"procVersion"`
	BaseBand    string        `json:"baseBand"`
	Version     Vivo50Version `json:"version"`
	SimInfo     string        `json:"simInfo"`
	OsType      string        `json:"osType"`
	MacAddress  string        `json:"macAddress"`
	WifiBSSID   string        `json:"wifiBSSID"`
	WifiSSID    string        `json:"wifiSSID"`
	ImsiMd5     string        `json:"imsiMd5"`
	Imei        string        `json:"imei"`
	Apn         string        `json:"apn"`
	AndroidID   string        `json:"androidId"`
	GUID        string        `json:"guid"`
}

// Vivo50Version 版本信息
type Vivo50Version struct {
	Incremental string `json:"incremental"`
	Release     string `json:"release"`
	Codename    string `json:"codename"`
	Sdk         int    `json:"sdk"`
}
