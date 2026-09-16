package s3camdev

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
)

func TestOnlineMusicIntentAndQueryExtraction(t *testing.T) {
	tests := map[string]string{
		"請播放 Day Dreamin 這首歌":         "Day Dreamin",
		"播放周杰倫的歌":                     "周杰倫",
		"帮我放一首 relaxing electronic":   "relaxing electronic",
		"播放音樂":                        "",
		"可以幫我播放音樂嗎":                   "",
		"放點音樂":                        "",
		"播歌":                          "",
		"我想听音乐":                       "",
		"來首歌":                         "",
		"幫我找一首歌來聽":                    "",
		"唱一首歌來聽":                      "",
		"幫我唱一首網路上的歌":                  "",
		"找一首 relaxing electronic 來播放": "relaxing electronic",
		"我要一點音樂":                      "",
		"放音樂給我聽":                      "",
		"播一首 Day Dreamin":             "Day Dreamin",
		"play a song electronic":      "electronic",
		"play some music":             "",
	}
	for transcript, expected := range tests {
		if !isOnlineMusicIntent(transcript) {
			t.Fatalf("online music intent missed: %q", transcript)
		}
		if query := extractOnlineMusicQuery(transcript); query != expected {
			t.Fatalf("unexpected query for %q: got %q want %q",
				transcript, query, expected)
		}
	}
	for _, transcript := range []string{
		"請唱一首原創歌", "清唱給我聽", "播放測試音", "搜尋音樂產業新聞", "你會播放音樂嗎",
		"停止播放音樂", "不要播放歌曲",
	} {
		if isOnlineMusicIntent(transcript) {
			t.Fatalf("non-playback request triggered online music: %q", transcript)
		}
	}
}

func TestAudiusSearchSelectsBoundedStreamableTrack(t *testing.T) {
	tracks := audiusSearchResponse{Data: []audiusTrack{
		{ID: "TooLong", Title: "Long set", Duration: 3600, IsStreamable: true,
			Access: struct {
				Stream bool `json:"stream"`
			}{Stream: true}},
		{ID: "Good123", Title: "Day Dreamin", Duration: 182, IsStreamable: true,
			User: struct {
				Name string `json:"name"`
			}{Name: "Independent Artist"}, Access: struct {
				Stream bool `json:"stream"`
			}{Stream: true}},
	}}
	payload, _ := json.Marshal(tracks)
	config := validOpenRouterPipelineConfig()
	config.HTTPClient = &http.Client{Transport: roundTripFunc(
		func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != audiusAPIBaseURL+
				"/tracks/search?limit=10&query=Day+Dreamin" ||
				request.Header.Get("Authorization") != "" {
				t.Fatalf("invalid Audius search request: %s headers=%v",
					request.URL, request.Header)
			}
			return &http.Response{StatusCode: http.StatusOK,
				Body:   io.NopCloser(strings.NewReader(string(payload))),
				Header: make(http.Header), Request: request}, nil
		})}
	pipeline, err := NewOpenRouterPipeline(config)
	if err != nil {
		t.Fatal(err)
	}
	track, found, err := pipeline.searchAudiusTrack(
		context.Background(), "Day Dreamin")
	if err != nil || !found || track.ID != "Good123" || track.Duration != 182 {
		t.Fatalf("unexpected Audius selection: track=%+v found=%t err=%v",
			track, found, err)
	}
}

func TestAudiusPlaybackTranscodesAuthorizedTrack(t *testing.T) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg is not installed")
	}
	const sampleRate = 24000
	pcm := make([]byte, sampleRate*16*2)
	for sample := 0; sample < sampleRate*16; sample++ {
		value := int16(math.Sin(float64(sample)*2*math.Pi*440/sampleRate) * 6000)
		binary.LittleEndian.PutUint16(pcm[sample*2:], uint16(value))
	}
	wav, err := encodePCM16WAV(pcm, sampleRate, 1)
	if err != nil {
		t.Fatal(err)
	}
	track := audiusTrack{ID: "Track123", Title: "Day Dreamin",
		Duration: 16, IsStreamable: true}
	track.User.Name = "Independent Artist"
	track.Access.Stream = true
	searchPayload, _ := json.Marshal(audiusSearchResponse{Data: []audiusTrack{track}})
	config := validOpenRouterPipelineConfig()
	config.FFmpegPath = ffmpeg
	config.HTTPClient = &http.Client{Transport: roundTripFunc(
		func(request *http.Request) (*http.Response, error) {
			var body []byte
			switch request.URL.String() {
			case audiusAPIBaseURL + "/tracks/search?limit=10&query=Day+Dreamin":
				body = searchPayload
			case audiusAPIBaseURL + "/tracks/Track123/stream":
				body = wav
			default:
				t.Fatalf("unexpected Audius request: %s", request.URL)
			}
			return &http.Response{StatusCode: http.StatusOK,
				Body:          io.NopCloser(strings.NewReader(string(body))),
				ContentLength: int64(len(body)), Header: make(http.Header),
				Request: request}, nil
		})}
	pipeline, err := NewOpenRouterPipeline(config)
	if err != nil {
		t.Fatal(err)
	}
	performance, err := pipeline.PlayOnlineMusic(
		context.Background(), "請播放 Day Dreamin 這首歌")
	if err != nil {
		t.Fatal(err)
	}
	if !performance.Music || len(performance.Packets) < 250 ||
		!strings.Contains(performance.DisplayText, "Day Dreamin") ||
		!strings.Contains(performance.DisplayText, "Independent Artist") {
		t.Fatalf("invalid Audius performance: text=%q packets=%d music=%t",
			performance.DisplayText, len(performance.Packets), performance.Music)
	}
}

func TestAudiusRedirectRejectsPrivateOrInsecureTargets(t *testing.T) {
	for _, raw := range []string{
		"http://audio.example.com/track.mp3",
		"https://127.0.0.1/track.mp3",
		"https://192.168.1.2/track.mp3",
		"https://localhost/track.mp3",
		"https://user:password@audio.example.com/track.mp3",
	} {
		parsed, _ := url.Parse(raw)
		if safeAudiusRedirect(&http.Request{URL: parsed, Header: make(http.Header)},
			[]*http.Request{{}}) == nil {
			t.Fatalf("unsafe redirect accepted: %s", raw)
		}
	}
	parsed, _ := url.Parse("https://audio.example.com/track.mp3")
	request := &http.Request{URL: parsed, Header: http.Header{
		"Authorization": []string{"Bearer secret"}, "Cookie": []string{"secret=1"},
	}}
	if err := safeAudiusRedirect(request, []*http.Request{{}}); err != nil ||
		request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
		t.Fatalf("safe public redirect rejected or credentials retained: %v", err)
	}
}
