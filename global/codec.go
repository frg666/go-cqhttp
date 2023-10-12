package global

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"os/exec"
	"path"

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

// EncodeMP4 将给定视频文件编码为MP4
func EncodeMP4(src string, dst string) error {
    cmd1 := exec.Command("gst-launch-1.0", "filesrc", "location="+src, "!", "decodebin", "!", "videoconvert", "!", "x264enc", "!", "mp4mux", "!", "filesink", "location="+dst)

    if err := cmd1.Run(); err != nil {
        if _, ok := err.(*exec.ExitError); !ok {
            cmd2 := exec.Command("gst-launch-1.0", "filesrc", "location="+src, "!", "decodebin", "!", "audioconvert", "!", "lamemp3enc", "!", "mp4mux", "!", "filesink", "location="+dst)

            if err := cmd2.Run(); err != nil {
                if _, ok := err.(*exec.ExitError); !ok {
                    return errors.Wrap(err, "convert mp4 failed")
                }
            }
        }
    }

    return nil
}

// ExtractCover 获取给定视频文件的Cover
func ExtractCover(src string, target string) error {
    cmd := exec.Command("gst-launch-1.0", "filesrc", "location="+src, "!", "decodebin", "!", "videoconvert", "!", "jpegenc", "!", "filesink", "location="+target)
    if err := cmd.Run(); err != nil {
        // 忽略 *exec.ExitError 错误
        if _, ok := err.(*exec.ExitError); !ok {
            return errors.Wrap(err, "extract video cover failed")
        }
    }
    return nil
}
