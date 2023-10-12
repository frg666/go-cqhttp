package global

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"os/exec"
	"path"
        "fmt"
	"github.com/pkg/errors"
        "github.com/notedit/gstreamer-go"
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

func ExtractCover(src string, target string) error {
    pipelineStr := "filesrc location=" + src + " ! decodebin ! videoconvert ! jpegenc ! filesink location=" + target

    pipeline, err := gst.ParseLaunch(pipelineStr)
    if err != nil {
        return err
    }

    defer pipeline.SetState(gst.StateNull())

    bus := pipeline.GetBus()
    defer bus.Unref()

    pipeline.SetState(gst.StatePlaying)

    for {
        message := bus.TimedPopFiltered(gst.CLOCK_TIME_NONE, gst.MessageTypeError|gst.MessageTypeEos)
        switch message.GetType() {
        case gst.MessageTypeError:
            err := message.ParseError()
            return fmt.Errorf("GStreamer error: %s", err.Message())
        case gst.MessageTypeEos:
            return nil
        }
    }
}
