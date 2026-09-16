package s3camdev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"xiaozhi-agent-platform/gateway/internal/opuspacket"
)

const (
	audiusAPIBaseURL       = "https://api.audius.co/v1"
	maxAudiusSearchBytes   = 2 * 1024 * 1024
	maxAudiusTrackBytes    = 24 * 1024 * 1024
	minAudiusTrackSeconds  = 15
	maxAudiusTrackSeconds  = 330
	maxAudiusSearchResults = 10
)

type audiusTrack struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	Duration        int    `json:"duration"`
	IsStreamable    bool   `json:"is_streamable"`
	ParentalWarning string `json:"parental_warning_type"`
	User            struct {
		Name string `json:"name"`
	} `json:"user"`
	Access struct {
		Stream bool `json:"stream"`
	} `json:"access"`
}

type audiusSearchResponse struct {
	Data []audiusTrack `json:"data"`
}

func isOnlineMusicIntent(transcript string) bool {
	text := normalizeAgentIntentText(transcript)
	if text == "" {
		return false
	}
	// ASR commonly confuses 找一首 (find a song) with 唱一首 (sing a song).
	// Playback cues win in an ambiguous utterance; original singing remains
	// available through unambiguous requests such as 請唱一首原創歌 or 清唱.
	playbackCue := containsAnyFolded(text, []string{
		"播放", "播歌", "播音樂", "放歌", "放音樂", "找一首", "找首",
		"找歌", "來聽", "網路", "現有歌曲", "原唱", "原曲",
		"play", "find a song", "listen to",
	})
	if isSingingIntent(text) && !playbackCue {
		return false
	}
	if containsAnyFolded(text, []string{
		"播放測試音", "播放語音", "播放錄音", "播放回覆",
		"play the test tone", "play the recording",
	}) {
		return false
	}
	if containsAnyFolded(text, []string{
		"你會播放", "你能播放", "是否支援播放", "支援播放音樂嗎",
		"can you play music", "do you support music playback",
	}) {
		return false
	}
	if containsAnyFolded(text, []string{
		"不要播放", "別播放", "停止播放", "關掉音樂", "關閉音樂",
		"don't play", "do not play", "stop playing",
	}) {
		return false
	}
	if playbackCue && containsAnyFolded(text, []string{
		"歌", "音樂", "music", "song", "track",
	}) {
		return true
	}
	if containsAnyFolded(text, []string{
		"播放歌曲", "播放音樂", "播放一首", "播放首歌", "播放點音樂",
		"播一首", "播首歌", "播歌", "播音樂", "播點音樂",
		"放一首", "放首歌", "放歌", "放音樂", "放點音樂", "放個歌",
		"幫我放一首", "帮我放一首", "請放一首", "请放一首",
		"來一首歌", "來首歌", "來點音樂", "找一首", "找首", "找歌來聽",
		"我想聽歌", "我要聽歌",
		"我想聽音樂", "我要聽音樂", "聽首歌", "聽音樂",
		"play a song", "play music", "play some music", "play the song",
	}) {
		return true
	}
	mediaNoun := containsAnyFolded(text, []string{"歌", "音樂", "music", "song", "track"})
	directPlayback := containsAnyFolded(text, []string{
		"播放", "播歌", "播音樂", "放歌", "放音樂",
	})
	if mediaNoun && directPlayback {
		return true
	}
	if mediaNoun && containsAnyFolded(text, []string{
		"幫我播放", "請播放", "可以播放", "想播放", "要播放",
		"幫我播", "請播", "可以播", "想播", "要播",
		"幫我放", "請放", "可以放", "想放", "要放",
		"想聽", "要聽", "讓我聽", "來聽", "來一首", "來首", "來點",
		"找一首", "找首", "找歌", "找音樂", "我要一", "我想要",
	}) {
		return true
	}
	return strings.HasPrefix(text, "播放 ") ||
		strings.HasPrefix(text, "請播放 ") ||
		(strings.HasPrefix(text, "播放") &&
			containsAnyFolded(text, []string{"歌", "音樂", "音乐"})) ||
		strings.HasPrefix(text, "play ")
}

func extractOnlineMusicQuery(transcript string) string {
	query := strings.TrimSpace(strings.NewReplacer(
		"请", "請", "帮", "幫", "给", "給", "听", "聽",
		"音乐", "音樂", "来", "來", "点", "點",
	).Replace(transcript))
	for _, prefix := range []string{
		"可以請你幫我播放", "可以幫我播放", "能不能幫我播放", "能幫我播放",
		"請幫我播放", "幫我播放", "請播放一下", "播放一下", "請播放", "播放",
		"可以請你幫我播", "可以幫我播", "能不能幫我播", "能幫我播",
		"請幫我播", "幫我播", "請播一下", "播一下", "請播", "播",
		"可以請你幫我放", "可以幫我放", "能不能幫我放", "能幫我放",
		"請幫我放", "幫我放", "請放一下", "放一下", "請放", "放",
		"我想聽", "我要聽", "想聽", "請讓我聽", "讓我聽", "請聽", "聽",
		"可以幫我找一首", "請幫我找一首", "幫我找一首", "幫我找首",
		"請幫我找", "幫我找", "隨便找一首", "隨便找首", "找一首", "找首", "找",
		"請幫我唱一首", "幫我唱一首", "唱一首",
		"給我來一首", "給我來首", "我想要", "我要",
		"請來一首", "來一首", "來首", "來點",
		"please play", "play a song", "play the song", "play music", "play",
	} {
		if len(query) >= len(prefix) && strings.EqualFold(query[:len(prefix)], prefix) {
			query = strings.TrimSpace(query[len(prefix):])
			break
		}
	}
	for _, filler := range []string{
		"給我", "一首", "首", "一點", "點", "一些", "些", "一個", "個",
		"some ", "a ", "the ",
	} {
		if strings.HasPrefix(query, filler) {
			query = strings.TrimSpace(strings.TrimPrefix(query, filler))
			break
		}
	}
	for {
		trimmed := strings.TrimSpace(strings.Trim(query, "，。！？!?：:、\"'"))
		changed := trimmed != query
		query = trimmed
		for _, suffix := range []string{
			"給我聽", "讓我聽", "來聽", "來播放", "播放一下", "播放",
			"這首歌", "一首歌", "的歌曲", "的歌",
			"歌曲", "音樂", " song", " music", " track",
		} {
			if strings.HasSuffix(query, suffix) {
				query = strings.TrimSpace(strings.TrimSuffix(query, suffix))
				changed = true
				break
			}
		}
		if !changed {
			break
		}
	}
	if containsAnyFolded(query, []string{
		"音樂", "歌曲", "歌", "music", "song", "songs", "track", "tracks",
	}) && utf8.RuneCountInString(query) <= 8 {
		query = ""
	}
	switch normalizeAgentIntentText(query) {
	case "網路上", "網路上的", "現有", "現有的", "原唱", "原曲":
		query = ""
	}
	if !utf8.ValidString(query) || utf8.RuneCountInString(query) > 120 ||
		strings.IndexFunc(query, unicode.IsControl) >= 0 {
		return ""
	}
	return query
}

func (pipeline *OpenRouterPipeline) PlayOnlineMusic(ctx context.Context,
	transcript string) (SongPerformance, error) {
	if pipeline == nil || !isOnlineMusicIntent(transcript) {
		return SongPerformance{}, fmt.Errorf("invalid online music request")
	}
	query := extractOnlineMusicQuery(transcript)
	track, found, err := pipeline.searchAudiusTrack(ctx, query)
	if err != nil {
		return SongPerformance{}, err
	}
	if !found {
		message := "目前在 Audius 開放音樂目錄找不到可播放的歌曲。"
		if query != "" {
			message = "Audius 找不到可播放的「" + query + "」。目前只能播放已授權的開放音樂目錄。"
		}
		packets, synthesizeErr := pipeline.Synthesize(ctx, message)
		if synthesizeErr != nil {
			return SongPerformance{}, synthesizeErr
		}
		return SongPerformance{DisplayText: message, Packets: packets}, nil
	}
	audio, err := pipeline.fetchAudiusTrack(ctx, track.ID)
	if err != nil {
		return SongPerformance{}, err
	}
	packets, err := pipeline.encodeAudiusMusicOpus(ctx, audio)
	if err != nil {
		return SongPerformance{}, err
	}
	display := "正在播放 Audius：" + track.Title
	if track.User.Name != "" {
		display += " — " + track.User.Name
	}
	return SongPerformance{DisplayText: display, Packets: packets, Music: true}, nil
}

func (pipeline *OpenRouterPipeline) searchAudiusTrack(ctx context.Context,
	query string) (audiusTrack, bool, error) {
	endpoint, _ := url.Parse(audiusAPIBaseURL + "/tracks/search")
	parameters := endpoint.Query()
	if query == "" {
		endpoint.Path = "/v1/tracks/trending"
		parameters.Set("time", "week")
	} else {
		parameters.Set("query", query)
	}
	parameters.Set("limit", strconv.Itoa(maxAudiusSearchResults))
	endpoint.RawQuery = parameters.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		endpoint.String(), nil)
	if err != nil {
		return audiusTrack{}, false, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := pipeline.httpClient.Do(request)
	if err != nil {
		return audiusTrack{}, false, fmt.Errorf("search Audius: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return audiusTrack{}, false, fmt.Errorf("search Audius: status %d",
			response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body,
		maxAudiusSearchBytes+1))
	var result audiusSearchResponse
	if err := decoder.Decode(&result); err != nil {
		return audiusTrack{}, false, fmt.Errorf("decode Audius search: %w", err)
	}
	for _, track := range result.Data {
		if validAudiusTrack(track) {
			return track, true, nil
		}
	}
	return audiusTrack{}, false, nil
}

func validAudiusTrack(track audiusTrack) bool {
	if track.ID == "" || len(track.ID) > 32 || track.Title == "" ||
		!utf8.ValidString(track.Title) || !utf8.ValidString(track.User.Name) ||
		utf8.RuneCountInString(track.Title) > 160 ||
		utf8.RuneCountInString(track.User.Name) > 80 ||
		track.Duration < minAudiusTrackSeconds ||
		track.Duration > maxAudiusTrackSeconds || !track.IsStreamable ||
		!track.Access.Stream || track.ParentalWarning != "" {
		return false
	}
	for _, character := range track.ID {
		if character > unicode.MaxASCII ||
			!(unicode.IsLetter(character) || unicode.IsDigit(character)) {
			return false
		}
	}
	return strings.IndexFunc(track.Title, unicode.IsControl) < 0 &&
		strings.IndexFunc(track.User.Name, unicode.IsControl) < 0
}

func (pipeline *OpenRouterPipeline) fetchAudiusTrack(ctx context.Context,
	trackID string) ([]byte, error) {
	if !validAudiusTrackID(trackID) {
		return nil, fmt.Errorf("invalid Audius track ID")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		audiusAPIBaseURL+"/tracks/"+url.PathEscape(trackID)+"/stream", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "audio/*,application/octet-stream")
	client := *pipeline.httpClient
	client.CheckRedirect = safeAudiusRedirect
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("stream Audius track: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		response.ContentLength > maxAudiusTrackBytes {
		return nil, fmt.Errorf("stream Audius track: invalid response")
	}
	audio, err := io.ReadAll(io.LimitReader(response.Body,
		maxAudiusTrackBytes+1))
	if err != nil || len(audio) == 0 || len(audio) > maxAudiusTrackBytes {
		return nil, fmt.Errorf("stream Audius track: invalid audio")
	}
	return audio, nil
}

func safeAudiusRedirect(request *http.Request, via []*http.Request) error {
	if request == nil || request.URL == nil || len(via) >= 8 ||
		request.URL.Scheme != "https" || request.URL.User != nil ||
		(request.URL.Port() != "" && request.URL.Port() != "443") {
		return fmt.Errorf("unsafe Audius redirect")
	}
	host := strings.TrimSuffix(strings.ToLower(request.URL.Hostname()), ".")
	if host == "" || host == "localhost" || !strings.Contains(host, ".") {
		return fmt.Errorf("unsafe Audius redirect host")
	}
	if address := net.ParseIP(host); address != nil &&
		(address.IsLoopback() || address.IsPrivate() || address.IsUnspecified() ||
			address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast()) {
		return fmt.Errorf("unsafe Audius redirect address")
	}
	request.Header.Del("Authorization")
	request.Header.Del("Cookie")
	return nil
}

func validAudiusTrackID(trackID string) bool {
	if trackID == "" || len(trackID) > 32 {
		return false
	}
	for _, character := range trackID {
		if character > unicode.MaxASCII ||
			!(unicode.IsLetter(character) || unicode.IsDigit(character)) {
			return false
		}
	}
	return true
}

func (pipeline *OpenRouterPipeline) encodeAudiusMusicOpus(ctx context.Context,
	audio []byte) ([][]byte, error) {
	ogg, err := pipeline.runFFmpeg(ctx, audio,
		"-i", "pipe:0", "-map", "0:a:0", "-t",
		strconv.Itoa(maxAudiusTrackSeconds), "-ac", "1", "-ar", "24000",
		"-af", "loudnorm=I=-11:LRA=9:TP=-0.5",
		"-c:a", "libopus", "-application", "audio", "-frame_duration", "60",
		"-vbr", "off", "-b:a", "24000", "-f", "opus", "pipe:1")
	if err != nil {
		return nil, fmt.Errorf("encode Audius music: %w", err)
	}
	packets, err := parseOggPackets(ogg)
	if err != nil || len(packets) < 3 || len(packets[0]) < 8 ||
		len(packets[1]) < 8 || string(packets[0][:8]) != "OpusHead" ||
		string(packets[1][:8]) != "OpusTags" {
		return nil, fmt.Errorf("Audius music returned invalid Ogg Opus")
	}
	packets = packets[2:]
	if len(packets) == 0 || len(packets) > maxSpokenReplyOpusPackets {
		return nil, fmt.Errorf("Audius track duration is out of range")
	}
	for _, packet := range packets {
		if err := opuspacket.ValidateMonoDuration(packet, opusFrameDurationMS); err != nil {
			return nil, fmt.Errorf("Audius Opus frame rejected: %w", err)
		}
	}
	return packets, nil
}
