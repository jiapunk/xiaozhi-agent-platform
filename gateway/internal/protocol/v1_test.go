package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
)

func validHello(version string) []byte {
	return []byte(`{"type":"hello","version":` + version +
		`,"transport":"websocket","features":{"device_agent":` +
		`{"version":1,"request_correlation":true}},"audio_params":` +
		`{"format":"opus","sample_rate":16000,"channels":1,"frame_duration":60}}`)
}

func TestDecodeClientHello(t *testing.T) {
	for _, version := range []string{"1", "2", "3"} {
		hello, parsed, err := DecodeClientHello(validHello(version))
		if err != nil {
			t.Fatalf("version %s: %v", version, err)
		}
		if parsed != int(version[0]-'0') || hello.AudioParams.SampleRate != 16000 {
			t.Fatalf("unexpected hello: %#v / %d", hello, parsed)
		}
	}
}

func TestRejectsBadHello(t *testing.T) {
	cases := [][]byte{
		[]byte(`{}`),
		[]byte(`{"type":"hello"}`),
		[]byte(`{"type":"hello","version":"1","transport":"websocket","features":{"device_agent":{"version":1,"request_correlation":true}},"audio_params":{"format":"opus","sample_rate":16000,"channels":1,"frame_duration":60}}`),
		[]byte(`{"type":"hello","version":1,"transport":"websocket","features":{},"audio_params":{"format":"opus","sample_rate":16000,"channels":1,"frame_duration":60}}`),
		[]byte(`{"type":"hello","version":1,"transport":"websocket","features":{"device_agent":{"version":1,"request_correlation":false}},"audio_params":{"format":"opus","sample_rate":16000,"channels":1,"frame_duration":60}}`),
		append(validHello("1"), []byte(` {}`)...),
	}
	for _, input := range cases {
		if _, _, err := DecodeClientHello(input); err == nil {
			t.Fatalf("expected rejection for %s", input)
		}
	}
}

func TestDecodeControlAndRequestIDs(t *testing.T) {
	message, id, err := DecodeControl([]byte(`{"session_id":"s1","type":"tts_request","request_id":42,"text":"ok"}`), "s1")
	if err != nil || id != 42 || message.Text != "ok" {
		t.Fatalf("unexpected result: %#v %d %v", message, id, err)
	}
	for _, value := range []string{"0", "-1", "1.5", "4294967296", `"1"`, "true"} {
		input := []byte(`{"session_id":"s1","type":"tts_request","request_id":` + value + `,"text":"ok"}`)
		if _, _, err := DecodeControl(input, "s1"); err == nil {
			t.Fatalf("expected request ID %s to fail", value)
		}
	}
	_, _, err = DecodeControl([]byte(`{"session_id":"old","type":"tts_abort","request_id":42,"reason":"barge_in"}`), "s1")
	if !errors.Is(err, ErrStale) {
		t.Fatalf("got %v, expected stale", err)
	}
}

func TestEncodeAudioPacket(t *testing.T) {
	opus := []byte{1, 2, 3}
	version1, _ := EncodeAudioPacket(1, opus)
	if string(version1) != string(opus) {
		t.Fatal("version 1 changed payload")
	}
	version2, _ := EncodeAudioPacket(2, opus)
	if len(version2) != 19 || binary.BigEndian.Uint16(version2[:2]) != 2 ||
		binary.BigEndian.Uint32(version2[12:16]) != 3 {
		t.Fatalf("invalid v2 packet: %v", version2)
	}
	version3, _ := EncodeAudioPacket(3, opus)
	if len(version3) != 7 || binary.BigEndian.Uint16(version3[2:4]) != 3 {
		t.Fatalf("invalid v3 packet: %v", version3)
	}
	for version, packet := range map[int][]byte{1: version1, 2: version2, 3: version3} {
		decoded, err := DecodeAudioPacket(version, packet)
		if err != nil || string(decoded) != string(opus) {
			t.Fatalf("version %d decode: %v %v", version, decoded, err)
		}
	}
}

func TestDecodeAudioPacketRejectsReservedBitsAndLengthMismatch(t *testing.T) {
	opus := []byte{1, 2, 3}
	version2, err := EncodeAudioPacket(2, opus)
	if err != nil {
		t.Fatal(err)
	}
	version2[7] = 1
	if _, err := DecodeAudioPacket(2, version2); err == nil {
		t.Fatal("expected non-zero v2 reserved field to fail")
	}

	version3, err := EncodeAudioPacket(3, opus)
	if err != nil {
		t.Fatal(err)
	}
	version3[1] = 1
	if _, err := DecodeAudioPacket(3, version3); err == nil {
		t.Fatal("expected non-zero v3 reserved byte to fail")
	}
	version3[1] = 0
	version3[3]++
	if _, err := DecodeAudioPacket(3, version3); err == nil {
		t.Fatal("expected v3 length mismatch to fail")
	}
}

func TestServerHelloJSONContract(t *testing.T) {
	hello, err := NewServerHello("voice:d1:c1", 24000, 60)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(hello)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["transport"] != "websocket" || decoded["session_id"] != "voice:d1:c1" {
		t.Fatalf("unexpected hello: %s", encoded)
	}
}
