package s3camdev

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"

	"xiaozhi-agent-platform/gateway/internal/opuspacket"
)

const (
	realtimePCMFrameBytes = 24000 * 2 * opusFrameDurationMS / 1000
	realtimeMaxOggPage    = 1024 * 1024
	realtimeOpusLookahead = 312
)

// realtimeOpusDecoder keeps one FFmpeg process alive for the full Realtime
// session. Feeding one Ogg page for every ESP32 Opus packet avoids spawning a
// process per frame and preserves the 60 ms device cadence.
type realtimeOpusDecoder struct {
	stdin    io.WriteCloser
	done     chan struct{}
	doneErr  error
	writeMu  sync.Mutex
	closeOne sync.Once
	serial   uint32
	sequence uint32
	granule  uint64
}

func newRealtimeOpusDecoder(ctx context.Context, ffmpegPath string,
	onPCM func([]byte) error) (*realtimeOpusDecoder, error) {
	command := exec.CommandContext(ctx, ffmpegPath,
		"-hide_banner", "-loglevel", "error", "-nostdin",
		"-probesize", "32", "-analyzeduration", "0",
		"-f", "ogg", "-blocksize", "4096", "-i", "pipe:0",
		"-map", "0:a:0", "-ac", "1", "-ar", "24000",
		"-f", "s16le", "pipe:1")
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open Realtime Opus decoder input: %w", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("open Realtime Opus decoder output: %w", err)
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start Realtime Opus decoder: %w", err)
	}
	decoder := &realtimeOpusDecoder{
		stdin: stdin, done: make(chan struct{}),
		serial: 0x53335254, sequence: 2, granule: 0,
	}
	if err := decoder.writeHeaders(); err != nil {
		_ = stdin.Close()
		_ = command.Wait()
		return nil, err
	}
	go func() {
		readErr := readRealtimePCM(stdout, onPCM)
		waitErr := command.Wait()
		if ctx.Err() != nil {
			decoder.doneErr = ctx.Err()
		} else if readErr != nil && !errors.Is(readErr, context.Canceled) {
			decoder.doneErr = readErr
		} else {
			decoder.doneErr = waitErr
		}
		close(decoder.done)
	}()
	return decoder, nil
}

func (decoder *realtimeOpusDecoder) writeHeaders() error {
	opusHead := append([]byte("OpusHead"), 1, 1)
	headerTail := make([]byte, 9)
	// Raw ESP32 packets start exactly at the first captured sample. Container
	// pre-skip would unnecessarily discard the beginning of each live session.
	binary.LittleEndian.PutUint16(headerTail[0:2], 0)
	binary.LittleEndian.PutUint32(headerTail[2:6], 16000)
	opusHead = append(opusHead, headerTail...)
	vendor := []byte("xiaozhi-realtime-gateway")
	opusTags := append([]byte("OpusTags"), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(opusTags[8:12], uint32(len(vendor)))
	opusTags = append(opusTags, vendor...)
	opusTags = append(opusTags, 0, 0, 0, 0)
	if _, err := decoder.stdin.Write(makeOggPage(
		opusHead, 0x02, 0, decoder.serial, 0)); err != nil {
		return fmt.Errorf("write Realtime Opus header: %w", err)
	}
	if _, err := decoder.stdin.Write(makeOggPage(
		opusTags, 0x00, 0, decoder.serial, 1)); err != nil {
		return fmt.Errorf("write Realtime Opus tags: %w", err)
	}
	return nil
}

func (decoder *realtimeOpusDecoder) WritePacket(packet []byte) error {
	if err := opuspacket.ValidateMonoDuration(packet, opusFrameDurationMS); err != nil {
		return fmt.Errorf("invalid Realtime microphone Opus frame: %w", err)
	}
	decoder.writeMu.Lock()
	defer decoder.writeMu.Unlock()
	decoder.granule += opusClockRate * opusFrameDurationMS / 1000
	page := makeOggPage(packet, 0, decoder.granule,
		decoder.serial, decoder.sequence)
	decoder.sequence++
	if _, err := decoder.stdin.Write(page); err != nil {
		return fmt.Errorf("write Realtime microphone frame: %w", err)
	}
	return nil
}

func (decoder *realtimeOpusDecoder) Close() error {
	decoder.closeOne.Do(func() {
		decoder.writeMu.Lock()
		_ = decoder.stdin.Close()
		decoder.writeMu.Unlock()
	})
	<-decoder.done
	return decoder.doneErr
}

func readRealtimePCM(reader io.Reader, onPCM func([]byte) error) error {
	for {
		frame := make([]byte, realtimePCMFrameBytes)
		bytesRead, err := io.ReadFull(reader, frame)
		if bytesRead > 0 {
			if callbackErr := onPCM(frame[:bytesRead]); callbackErr != nil {
				return callbackErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
	}
}

// realtimeOpusEncoder converts OpenAI's PCM16/24 kHz stream back into the raw
// 60 ms Opus packets expected by the ESP32. Ogg headers stay inside the
// Gateway; only validated audio packets cross the device WebSocket.
type realtimeOpusEncoder struct {
	stdin    io.WriteCloser
	done     chan struct{}
	doneErr  error
	writeMu  sync.Mutex
	closeOne sync.Once
}

func newRealtimeOpusEncoder(ctx context.Context, ffmpegPath string,
	onPacket func([]byte) error) (*realtimeOpusEncoder, error) {
	command := exec.CommandContext(ctx, ffmpegPath,
		"-hide_banner", "-loglevel", "error", "-nostdin",
		"-probesize", "32", "-analyzeduration", "0",
		"-f", "s16le", "-ar", "24000", "-ac", "1",
		"-blocksize", "2880", "-i", "pipe:0",
		"-map", "0:a:0", "-c:a", "libopus", "-application", "lowdelay",
		"-frame_duration", "60", "-b:a", "32k", "-vbr", "constrained",
		"-compression_level", "5", "-f", "ogg",
		"-page_duration", "60000", "-flush_packets", "1",
		"-blocksize", "4096", "pipe:1")
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open Realtime Opus encoder input: %w", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("open Realtime Opus encoder output: %w", err)
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start Realtime Opus encoder: %w", err)
	}
	// libopus needs a small lookahead before it can emit the first 60 ms
	// packet. Priming with silence avoids waiting for a second provider chunk;
	// the ESP32 receives immediate, harmless leading silence instead.
	if _, err := stdin.Write(make([]byte, realtimeOpusLookahead*2)); err != nil {
		_ = stdin.Close()
		_ = command.Wait()
		return nil, fmt.Errorf("prime Realtime Opus encoder: %w", err)
	}
	encoder := &realtimeOpusEncoder{stdin: stdin, done: make(chan struct{})}
	go func() {
		readErr := readRealtimeOggPackets(stdout, func(packet []byte) error {
			if len(packet) >= 8 &&
				(string(packet[:8]) == "OpusHead" || string(packet[:8]) == "OpusTags") {
				return nil
			}
			if err := opuspacket.ValidateMonoDuration(
				packet, opusFrameDurationMS); err != nil {
				return fmt.Errorf("FFmpeg emitted invalid Realtime Opus frame: %w", err)
			}
			return onPacket(packet)
		})
		waitErr := command.Wait()
		if ctx.Err() != nil {
			encoder.doneErr = ctx.Err()
		} else if readErr != nil {
			encoder.doneErr = readErr
		} else {
			encoder.doneErr = waitErr
		}
		close(encoder.done)
	}()
	return encoder, nil
}

func (encoder *realtimeOpusEncoder) WritePCM(pcm []byte) error {
	if len(pcm) == 0 || len(pcm)%2 != 0 {
		return fmt.Errorf("invalid Realtime PCM audio")
	}
	encoder.writeMu.Lock()
	defer encoder.writeMu.Unlock()
	if _, err := encoder.stdin.Write(pcm); err != nil {
		return fmt.Errorf("write Realtime PCM audio: %w", err)
	}
	return nil
}

func (encoder *realtimeOpusEncoder) Close() error {
	encoder.closeOne.Do(func() {
		encoder.writeMu.Lock()
		_ = encoder.stdin.Close()
		encoder.writeMu.Unlock()
	})
	<-encoder.done
	return encoder.doneErr
}

func readRealtimeOggPackets(reader io.Reader, onPacket func([]byte) error) error {
	buffered := bufio.NewReader(reader)
	var current []byte
	for {
		header := make([]byte, 27)
		if _, err := io.ReadFull(buffered, header); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("read Realtime Ogg header: %w", err)
		}
		if string(header[:4]) != "OggS" || header[4] != 0 {
			return fmt.Errorf("invalid Realtime Ogg page")
		}
		segmentTable := make([]byte, int(header[26]))
		if _, err := io.ReadFull(buffered, segmentTable); err != nil {
			return fmt.Errorf("read Realtime Ogg lacing: %w", err)
		}
		payloadBytes := 0
		for _, length := range segmentTable {
			payloadBytes += int(length)
		}
		if payloadBytes > realtimeMaxOggPage {
			return fmt.Errorf("Realtime Ogg page is too large")
		}
		payload := make([]byte, payloadBytes)
		if _, err := io.ReadFull(buffered, payload); err != nil {
			return fmt.Errorf("read Realtime Ogg payload: %w", err)
		}
		offset := 0
		for _, lengthByte := range segmentTable {
			length := int(lengthByte)
			current = append(current, payload[offset:offset+length]...)
			offset += length
			if length < 255 {
				if err := onPacket(append([]byte(nil), current...)); err != nil {
					return err
				}
				current = current[:0]
			}
		}
	}
	if len(current) != 0 {
		return fmt.Errorf("unterminated Realtime Ogg packet")
	}
	return nil
}
