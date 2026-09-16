package s3camdev

import (
	"bytes"
	"testing"
)

func TestDeviceImageUploadIsBoundedAndRequestCorrelated(t *testing.T) {
	session := newDeviceSession(&Server{}, nil, "test-session")
	requestID := "image-0123456789abcdef0123456789abcdef"
	delivery, cleanup, err := session.registerImage(requestID)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if !session.beginImage(requestID, "yuyv422", 320, 240,
		maxDeviceImageBytes) {
		t.Fatal("valid image metadata rejected")
	}
	first := bytes.Repeat([]byte{0x80}, maxDeviceImageBytes/2)
	second := bytes.Repeat([]byte{0x40}, maxDeviceImageBytes-len(first))
	if !session.appendImage(first) || !session.appendImage(second) ||
		!session.finishImage(requestID, "end") {
		t.Fatal("valid image upload rejected")
	}
	result := <-delivery
	if result.err != nil || result.image.Format != "yuyv422" ||
		result.image.Width != 320 || result.image.Height != 240 ||
		len(result.image.Data) != maxDeviceImageBytes ||
		result.image.Data[0] != 0x80 ||
		result.image.Data[len(result.image.Data)-1] != 0x40 {
		t.Fatalf("unexpected image delivery: format=%q size=%dx%d bytes=%d err=%v",
			result.image.Format, result.image.Width, result.image.Height,
			len(result.image.Data), result.err)
	}
}

func TestDeviceImageUploadRejectsWrongGeometry(t *testing.T) {
	session := newDeviceSession(&Server{}, nil, "test-session")
	requestID := "image-fedcba9876543210fedcba9876543210"
	delivery, cleanup, err := session.registerImage(requestID)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if session.beginImage(requestID, "yuyv422", 640, 480, 640*480*2) {
		t.Fatal("oversized image metadata accepted")
	}
	if result := <-delivery; result.err == nil {
		t.Fatal("invalid image metadata did not fail the waiting tool")
	}
}
