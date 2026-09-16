// Package opuspacket validates the self-delimiting structure and TOC policy of
// Opus packets without decoding audio samples.
package opuspacket

import "fmt"

const maximumFrameBytes = 1275

type Info struct {
	Stereo                  bool
	FrameCount              int
	FrameDurationMicrosecs  int
	PacketDurationMicrosecs int
}

func Parse(packet []byte) (Info, error) {
	if len(packet) < 1 {
		return Info{}, fmt.Errorf("Opus packet has no TOC byte")
	}
	toc := packet[0]
	config := int(toc >> 3)
	frameDuration := frameDurationMicrosecs(config)
	stereo := toc&0x04 != 0
	code := int(toc & 0x03)
	frameCount := 1

	switch code {
	case 0:
		if err := validFrameSize(len(packet) - 1); err != nil {
			return Info{}, err
		}
	case 1:
		payload := len(packet) - 1
		if payload%2 != 0 {
			return Info{}, fmt.Errorf("Opus CBR pair has unequal frame sizes")
		}
		if err := validFrameSize(payload / 2); err != nil {
			return Info{}, err
		}
		frameCount = 2
	case 2:
		firstSize, consumed, err := parseSize(packet[1:])
		if err != nil {
			return Info{}, err
		}
		secondSize := len(packet) - 1 - consumed - firstSize
		if err := validFrameSize(firstSize); err != nil {
			return Info{}, err
		}
		if err := validFrameSize(secondSize); err != nil {
			return Info{}, err
		}
		frameCount = 2
	case 3:
		count, err := validateArbitraryFrames(packet)
		if err != nil {
			return Info{}, err
		}
		frameCount = count
	}

	packetDuration := frameDuration * frameCount
	if packetDuration > 120000 {
		return Info{}, fmt.Errorf("Opus packet duration exceeds 120 ms")
	}
	return Info{
		Stereo: stereo, FrameCount: frameCount,
		FrameDurationMicrosecs:  frameDuration,
		PacketDurationMicrosecs: packetDuration,
	}, nil
}

func ValidateMonoDuration(packet []byte, expectedMillis int) error {
	if expectedMillis <= 0 || expectedMillis > 120 {
		return fmt.Errorf("invalid expected Opus duration")
	}
	info, err := Parse(packet)
	if err != nil {
		return err
	}
	if info.Stereo {
		return fmt.Errorf("stereo Opus is not allowed")
	}
	if info.PacketDurationMicrosecs != expectedMillis*1000 {
		return fmt.Errorf("Opus packet duration differs from %d ms", expectedMillis)
	}
	return nil
}

func frameDurationMicrosecs(config int) int {
	switch {
	case config < 12:
		return []int{10000, 20000, 40000, 60000}[config&3]
	case config < 16:
		return []int{10000, 20000}[config&1]
	default:
		return []int{2500, 5000, 10000, 20000}[config&3]
	}
}

func parseSize(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("truncated Opus frame size")
	}
	if data[0] < 252 {
		return int(data[0]), 1, nil
	}
	if len(data) < 2 {
		return 0, 0, fmt.Errorf("truncated Opus extended frame size")
	}
	return int(data[0]) + 4*int(data[1]), 2, nil
}

func validFrameSize(size int) error {
	// RFC 6716 section 3.2.1 permits a zero-byte frame for DTX or a lost
	// packet. The TOC still carries the mode, channel, and duration policy.
	if size < 0 || size > maximumFrameBytes {
		return fmt.Errorf("invalid Opus frame size")
	}
	return nil
}

func validateArbitraryFrames(packet []byte) (int, error) {
	if len(packet) < 2 {
		return 0, fmt.Errorf("truncated Opus arbitrary-frame packet")
	}
	header := packet[1]
	frameCount := int(header & 0x3f)
	if frameCount == 0 || frameCount > 48 {
		return 0, fmt.Errorf("invalid Opus frame count")
	}
	index := 2
	padding := 0
	if header&0x40 != 0 {
		for {
			if index >= len(packet) {
				return 0, fmt.Errorf("truncated Opus padding")
			}
			value := int(packet[index])
			index++
			if value == 255 {
				padding += 254
			} else {
				padding += value
				break
			}
			if padding >= len(packet) {
				return 0, fmt.Errorf("invalid Opus padding")
			}
		}
	}
	payloadEnd := len(packet) - padding
	if payloadEnd < index {
		return 0, fmt.Errorf("invalid Opus padding length")
	}

	if header&0x80 == 0 {
		payload := payloadEnd - index
		if payload%frameCount != 0 {
			return 0, fmt.Errorf("Opus CBR packet has unequal frame sizes")
		}
		if err := validFrameSize(payload / frameCount); err != nil {
			return 0, err
		}
		return frameCount, nil
	}

	declared := 0
	for frame := 0; frame < frameCount-1; frame++ {
		size, consumed, err := parseSize(packet[index:payloadEnd])
		if err != nil {
			return 0, err
		}
		index += consumed
		if err := validFrameSize(size); err != nil {
			return 0, err
		}
		declared += size
		if declared > payloadEnd-index {
			return 0, fmt.Errorf("Opus VBR frame lengths exceed payload")
		}
	}
	lastSize := payloadEnd - index - declared
	if err := validFrameSize(lastSize); err != nil {
		return 0, err
	}
	return frameCount, nil
}
