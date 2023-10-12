package global

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"os/exec"
	"path"
        "fmt"
	"github.com/pkg/errors"

	"github.com/Mrs4s/go-cqhttp/internal/base"
)

// EncoderSilk 将音频编码为Silk
func EncoderSilk(data []byte) ([]byte, error) {
	h := md5.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, errors.Wrap(err, "calc md5 failed")
	}
	tempName := hex.EncodeToString(h.Sum(nil))
	if silkPath := path.Join("data/cache", tempName+".silk"); PathExists(silkPath) {
		return os.ReadFile(silkPath)
	}
	slk, err := base.EncodeSilk(data, tempName)
	if err != nil {
		return nil, errors.Wrap(err, "encode silk failed")
	}
	return slk, nil
}

func EncodeMP4(src, dst string) error {
	cmd := exec.Command("ffmpeg", "-i", src, "-y", "-c:v", "h264", "-c:a", "mp3", dst)
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("ffmpeg", "-i", src, "-y", "-c", "copy", "-map", "0", dst)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to encode MP4: %v", err)
		}
	}
	return nil
}

func ExtractCover(src, target string) error {
	cmd := exec.Command("ffmpeg", "-i", src, "-y", "-ss", "0", target)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to extract video cover: %v", err)
	}
	return nil
}
