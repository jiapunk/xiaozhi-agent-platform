package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	AgentVersion       = 1
	MaxControlBytes    = 4096
	MaxSessionIDBytes  = 63
	MaxSTTTextBytes    = 2048
	MaxTTSTextBytes    = 512
	MaxOpusPacketBytes = 4096
)

var ErrStale = errors.New("stale session or request")

type Violation struct {
	Code   string
	Detail string
}

func (v *Violation) Error() string { return v.Code + ": " + v.Detail }

type StrictNumber string

func (number *StrictNumber) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || data[0] == '"' || string(data) == "null" ||
		string(data) == "true" || string(data) == "false" {
		return fmt.Errorf("expected a JSON number")
	}
	if _, err := strconv.ParseFloat(string(data), 64); err != nil {
		return fmt.Errorf("expected a JSON number")
	}
	*number = StrictNumber(string(data))
	return nil
}

func (number StrictNumber) Float64() (float64, error) {
	return strconv.ParseFloat(string(number), 64)
}

type DeviceAgentFeature struct {
	Version            StrictNumber `json:"version"`
	RequestCorrelation bool         `json:"request_correlation"`
}

type ClientFeatures struct {
	DeviceAgent *DeviceAgentFeature `json:"device_agent"`
}

type AudioParams struct {
	Format        string `json:"format"`
	SampleRate    int    `json:"sample_rate"`
	Channels      int    `json:"channels"`
	FrameDuration int    `json:"frame_duration"`
}

type ClientHello struct {
	Type        string         `json:"type"`
	Version     StrictNumber   `json:"version"`
	Transport   string         `json:"transport"`
	Features    ClientFeatures `json:"features"`
	AudioParams AudioParams    `json:"audio_params"`
}

type ServerHello struct {
	Type        string         `json:"type"`
	Transport   string         `json:"transport"`
	SessionID   string         `json:"session_id"`
	Features    ServerFeatures `json:"features"`
	AudioParams AudioParams    `json:"audio_params"`
}

type ServerFeatures struct {
	DeviceAgent ServerDeviceAgentFeature `json:"device_agent"`
}

type ServerDeviceAgentFeature struct {
	Version            int  `json:"version"`
	RequestCorrelation bool `json:"request_correlation"`
}

type ControlMessage struct {
	SessionID string       `json:"session_id"`
	Type      string       `json:"type"`
	RequestID StrictNumber `json:"request_id"`
	Text      string       `json:"text,omitempty"`
	Reason    string       `json:"reason,omitempty"`
}

type TTSEvent struct {
	SessionID string `json:"session_id"`
	Type      string `json:"type"`
	State     string `json:"state"`
	RequestID uint32 `json:"request_id"`
	Text      string `json:"text,omitempty"`
	Code      string `json:"code,omitempty"`
}

type ErrorEvent struct {
	Type string `json:"type"`
	Code string `json:"code"`
}

func DecodeClientHello(data []byte) (ClientHello, int, error) {
	var hello ClientHello
	if err := decodeOne(data, &hello); err != nil {
		return ClientHello{}, 0, violation("invalid_hello", err.Error())
	}
	if hello.Type != "hello" || hello.Transport != "websocket" {
		return ClientHello{}, 0, violation("invalid_hello", "type/transport mismatch")
	}
	version, err := exactInt(hello.Version, 1, 3)
	if err != nil {
		return ClientHello{}, 0, violation("unsupported_transport_version", err.Error())
	}
	if hello.Features.DeviceAgent == nil {
		return ClientHello{}, 0, violation("missing_device_agent", "feature is required")
	}
	agentVersion, err := exactInt(hello.Features.DeviceAgent.Version, AgentVersion, AgentVersion)
	if err != nil || agentVersion != AgentVersion {
		return ClientHello{}, 0, violation("unsupported_agent_version", "version 1 is required")
	}
	if !hello.Features.DeviceAgent.RequestCorrelation {
		return ClientHello{}, 0, violation("missing_request_correlation", "explicit true is required")
	}
	if hello.AudioParams.Format != "opus" || hello.AudioParams.Channels != 1 ||
		hello.AudioParams.SampleRate <= 0 || hello.AudioParams.SampleRate > 48000 ||
		hello.AudioParams.FrameDuration < 20 || hello.AudioParams.FrameDuration > 120 {
		return ClientHello{}, 0, violation("invalid_audio_params", "unsupported Opus parameters")
	}
	return hello, version, nil
}

func NewServerHello(sessionID string, outputSampleRate, frameDuration int) (ServerHello, error) {
	if err := validString(sessionID, MaxSessionIDBytes); err != nil {
		return ServerHello{}, violation("invalid_session", err.Error())
	}
	if outputSampleRate <= 0 || outputSampleRate > 48000 ||
		frameDuration <= 0 || frameDuration > 120 {
		return ServerHello{}, violation("invalid_audio_params", "unsupported output parameters")
	}
	return ServerHello{
		Type:      "hello",
		Transport: "websocket",
		SessionID: sessionID,
		Features: ServerFeatures{DeviceAgent: ServerDeviceAgentFeature{
			Version: AgentVersion, RequestCorrelation: true,
		}},
		AudioParams: AudioParams{
			Format: "opus", SampleRate: outputSampleRate, Channels: 1,
			FrameDuration: frameDuration,
		},
	}, nil
}

func DecodeControl(data []byte, sessionID string) (ControlMessage, uint32, error) {
	var message ControlMessage
	if err := decodeOne(data, &message); err != nil {
		return ControlMessage{}, 0, violation("invalid_json", err.Error())
	}
	if message.SessionID != sessionID {
		return ControlMessage{}, 0, fmt.Errorf("%w: session_id mismatch", ErrStale)
	}
	requestID, err := ParseRequestID(message.RequestID)
	if err != nil {
		return ControlMessage{}, 0, err
	}
	switch message.Type {
	case "tts_request":
		if err := validString(message.Text, MaxTTSTextBytes); err != nil {
			return ControlMessage{}, 0, violation("invalid_tts_text", err.Error())
		}
	case "tts_abort":
		if !validAbortReason(message.Reason) {
			return ControlMessage{}, 0, violation("invalid_abort_reason", "unsupported reason")
		}
	default:
		return ControlMessage{}, 0, violation("unsupported_message", "unsupported Agent control type")
	}
	return message, requestID, nil
}

func ParseRequestID(number StrictNumber) (uint32, error) {
	value, err := number.Float64()
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) ||
		value < 1 || value > math.MaxUint32 || math.Trunc(value) != value {
		return 0, violation("invalid_request_id", "request_id must be a uint32 integer")
	}
	return uint32(value), nil
}

func EncodeAudioPacket(version int, opus []byte) ([]byte, error) {
	if len(opus) == 0 || len(opus) > MaxOpusPacketBytes {
		return nil, violation("invalid_audio_packet", "Opus packet size is out of range")
	}
	switch version {
	case 1:
		return append([]byte(nil), opus...), nil
	case 2:
		output := make([]byte, 16+len(opus))
		binary.BigEndian.PutUint16(output[0:2], 2)
		binary.BigEndian.PutUint16(output[2:4], 0)
		binary.BigEndian.PutUint32(output[4:8], 0)
		binary.BigEndian.PutUint32(output[8:12], 0)
		binary.BigEndian.PutUint32(output[12:16], uint32(len(opus)))
		copy(output[16:], opus)
		return output, nil
	case 3:
		output := make([]byte, 4+len(opus))
		output[0] = 0
		output[1] = 0
		binary.BigEndian.PutUint16(output[2:4], uint16(len(opus)))
		copy(output[4:], opus)
		return output, nil
	default:
		return nil, violation("unsupported_transport_version", "version must be 1, 2, or 3")
	}
}

func DecodeAudioPacket(version int, packet []byte) ([]byte, error) {
	var opus []byte
	switch version {
	case 1:
		opus = packet
	case 2:
		if len(packet) < 16 || binary.BigEndian.Uint16(packet[0:2]) != 2 ||
			binary.BigEndian.Uint16(packet[2:4]) != 0 ||
			binary.BigEndian.Uint32(packet[4:8]) != 0 {
			return nil, violation("invalid_audio_packet", "invalid version 2 header")
		}
		length := int(binary.BigEndian.Uint32(packet[12:16]))
		if length != len(packet)-16 {
			return nil, violation("invalid_audio_packet", "version 2 length mismatch")
		}
		opus = packet[16:]
	case 3:
		if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 {
			return nil, violation("invalid_audio_packet", "invalid version 3 header")
		}
		length := int(binary.BigEndian.Uint16(packet[2:4]))
		if length != len(packet)-4 {
			return nil, violation("invalid_audio_packet", "version 3 length mismatch")
		}
		opus = packet[4:]
	default:
		return nil, violation("unsupported_transport_version", "version must be 1, 2, or 3")
	}
	if len(opus) == 0 || len(opus) > MaxOpusPacketBytes {
		return nil, violation("invalid_audio_packet", "Opus packet size is out of range")
	}
	return append([]byte(nil), opus...), nil
}

func decodeOne(data []byte, destination any) error {
	if len(data) == 0 || len(data) > MaxControlBytes {
		return fmt.Errorf("control message must be 1..%d bytes", MaxControlBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

func exactInt(number StrictNumber, minimum, maximum int) (int, error) {
	value, err := number.Float64()
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) ||
		math.Trunc(value) != value || value < float64(minimum) || value > float64(maximum) {
		return 0, fmt.Errorf("number must be an integer from %d through %d", minimum, maximum)
	}
	return int(value), nil
}

func validString(value string, maxBytes int) error {
	if !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return fmt.Errorf("value must be non-empty")
	}
	if len([]byte(value)) > maxBytes {
		return fmt.Errorf("value exceeds %d UTF-8 bytes", maxBytes)
	}
	return nil
}

func validAbortReason(reason string) bool {
	switch reason {
	case "barge_in", "button", "network_lost", "session_closed":
		return true
	default:
		return false
	}
}

func violation(code, detail string) error {
	return &Violation{Code: code, Detail: detail}
}
