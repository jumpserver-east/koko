package proxy

import (
	"errors"
	"testing"

	"github.com/jumpserver/koko/pkg/jms-sdk-go/httplib"
)

func TestGetCommandFaceReviewErrorMessage(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "api detail",
			err: &httplib.APIError{
				StatusCode: 400,
				Detail:     "人脸核验失败：调用拍照系统失败（摄像头离线）",
			},
			want: "人脸核验失败：调用拍照系统失败",
		},
		{
			name: "api code fallback",
			err: &httplib.APIError{
				StatusCode: 400,
				Code:       "face_verify_photo_timeout",
			},
			want: "人脸核验失败：等待拍照系统回调超时",
		},
		{
			name: "api detail before generic code",
			err: &httplib.APIError{
				StatusCode: 400,
				Code:       "face_verify_compare_failed",
				Detail:     "人脸核验失败：拍照系统回调图片异常",
			},
			want: "人脸核验失败：拍照系统回调图片异常",
		},
		{
			name: "camera face missing",
			err: &httplib.APIError{
				StatusCode: 400,
				Code:       "face_verify_compare_failed",
				Detail:     "人脸核验失败：拍照系统未返回用户人脸信息",
			},
			want: "人脸核验失败：拍照系统未返回用户人脸信息",
		},
		{
			name: "face compare failed count",
			err: &httplib.APIError{
				StatusCode: 400,
				Code:       "face_verify_rejected",
				Detail:     "人脸核验失败：AI 人脸比对不通过，当前连续失败 2 次，连续失败 3 次将中断会话",
			},
			want: "人脸核验失败：人脸比对不通过，当前连续失败 2 次，连续失败 3 次将中断会话",
		},
		{
			name: "low level error",
			err:  errors.New("Post \"http://core/api/\": dial tcp: connection refused"),
			want: "人脸核验失败：Core 或外部人脸核验服务异常",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := getCommandFaceReviewErrorMessage(tt.err)
			if got != tt.want {
				t.Fatalf("want %q, got %q", tt.want, got)
			}
		})
	}
}
