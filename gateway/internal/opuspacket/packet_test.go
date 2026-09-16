package opuspacket

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

type codecFixtureManifest struct {
	Fixtures []struct {
		Name        string `json:"name"`
		Packet      string `json:"packet_base64"`
		Channels    int    `json:"channels"`
		DurationMS  int    `json:"duration_ms"`
		SampleRate  int    `json:"sample_rate_hz"`
		SampleCount int    `json:"decoded_sample_count"`
	} `json:"fixtures"`
}

func TestParsesProductMonoSixtyMillisecondPackets(t *testing.T) {
	cases := []struct {
		name   string
		packet []byte
		frames int
	}{
		{"one 60 ms SILK frame", []byte{0x18, 0x00}, 1},
		{"three 20 ms CBR frames", []byte{0x0b, 0x03, 0x00, 0x00, 0x00}, 3},
		{"three 20 ms VBR frames", []byte{0x0b, 0x83, 0x01, 0x01, 0x00, 0x00, 0x00}, 3},
		{"three 20 ms padded frames", []byte{0x0b, 0x43, 0x01, 0x00, 0x00, 0x00, 0x00}, 3},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			info, err := Parse(test.packet)
			if err != nil {
				t.Fatal(err)
			}
			if info.Stereo || info.FrameCount != test.frames ||
				info.PacketDurationMicrosecs != 60000 {
				t.Fatalf("unexpected info: %#v", info)
			}
			if err := ValidateMonoDuration(test.packet, 60); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParsesRFC6716DiscontinuousTransmissionFrames(t *testing.T) {
	for _, test := range []struct {
		packet     []byte
		durationMS int
		frames     int
	}{
		{[]byte{0x18}, 60, 1},
		{[]byte{0x09}, 40, 2},
		{[]byte{0x0a, 0x00}, 40, 2},
		{[]byte{0x0b, 0x03}, 60, 3},
	} {
		info, err := Parse(test.packet)
		if err != nil {
			t.Fatal(err)
		}
		if info.FrameCount != test.frames ||
			info.PacketDurationMicrosecs != test.durationMS*1000 {
			t.Fatalf("unexpected DTX info: %#v", info)
		}
		if err := ValidateMonoDuration(test.packet, test.durationMS); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParsesTwoFrameModes(t *testing.T) {
	for _, packet := range [][]byte{
		{0x09, 0x00, 0x00},
		{0x0a, 0x01, 0x00, 0x00},
	} {
		info, err := Parse(packet)
		if err != nil || info.FrameCount != 2 || info.PacketDurationMicrosecs != 40000 {
			t.Fatalf("unexpected parse: info=%#v err=%v", info, err)
		}
	}
}

func TestRejectsWrongProductAudioPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		packet []byte
	}{
		{"stereo", []byte{0x1c, 0x00}},
		{"twenty milliseconds", []byte{0x08, 0x00}},
		{"too long", []byte{0x1b, 0x03, 0x00, 0x00, 0x00}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateMonoDuration(test.packet, 60); err == nil {
				t.Fatal("expected product policy rejection")
			}
		})
	}
}

func TestRejectsMalformedPacketLayouts(t *testing.T) {
	packets := [][]byte{
		nil,
		{0x09, 0x00},
		{0x0a, 0xfc},
		{0x0a, 0x02, 0x00},
		{0x0b, 0x00, 0x00},
		{0x0b, 0x43, 0xff},
		{0x0b, 0x43, 0x05, 0x00},
		{0x0b, 0x83, 0x05, 0x05, 0x00},
	}
	for index, packet := range packets {
		if _, err := Parse(packet); err == nil {
			t.Fatalf("packet %d unexpectedly passed", index)
		}
	}
}

func TestRejectsInvalidExpectedDuration(t *testing.T) {
	if err := ValidateMonoDuration([]byte{0x18, 0x00}, 0); err == nil {
		t.Fatal("expected invalid duration rejection")
	}
}

func TestReferenceDecodedProductFixturesPassPacketPolicy(t *testing.T) {
	data, err := os.ReadFile("../../testdata/speech/opus-codec-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest codecFixtureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Fixtures) != 2 {
		t.Fatalf("expected two reference fixtures, got %d", len(manifest.Fixtures))
	}
	for _, fixture := range manifest.Fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			packet, err := base64.StdEncoding.Strict().DecodeString(fixture.Packet)
			if err != nil {
				t.Fatal(err)
			}
			if fixture.Channels != 1 || fixture.DurationMS != 60 {
				t.Fatalf("fixture violates product policy: %#v", fixture)
			}
			expectedSamples := fixture.SampleRate * fixture.DurationMS / 1000
			if fixture.SampleCount != expectedSamples {
				t.Fatalf("fixture sample count = %d, want %d", fixture.SampleCount, expectedSamples)
			}
			if err := ValidateMonoDuration(packet, fixture.DurationMS); err != nil {
				t.Fatalf("reference-decoded fixture fails structural policy: %v", err)
			}
		})
	}
}
