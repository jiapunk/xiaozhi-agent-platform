package s3camdev

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	voiceProfileHeader      = "XZVOICE1"
	maximumVoiceUpload      = 8 * 1024 * 1024
	maximumVoiceSampleWAV   = 90 * 24000 * 2
	minimumVoiceSampleWAV   = 8 * 24000 * 2
	voiceEnrollmentLifetime = 10 * time.Minute
)

type VoiceCloneConfig struct {
	APIKey         string
	ManagementURL  string
	TTSURL         string
	TargetModel    string
	VoicePrefix    string
	PublicHTTPSURL string
	FFmpegPath     string
	ProfileFile    string
	ProfileKey     string
	HTTPClient     *http.Client
}

type voiceProfile struct {
	VoiceID   string `json:"voice_id"`
	Model     string `json:"model"`
	CreatedAt string `json:"created_at"`
	Active    bool   `json:"active"`
}

type voiceEnrollment struct {
	Code      string
	Token     string
	ExpiresAt time.Time
}

type voiceSample struct {
	WAV       []byte
	ExpiresAt time.Time
	Fetches   int
}

type VoiceCloneService struct {
	config VoiceCloneConfig
	client *http.Client
	aead   cipher.AEAD

	mu         sync.Mutex
	profile    voiceProfile
	enrollment voiceEnrollment
	samples    map[string]*voiceSample
}

func NewVoiceCloneService(config VoiceCloneConfig) (*VoiceCloneService, error) {
	if err := validateSecret(config.APIKey); err != nil {
		return nil, fmt.Errorf("voice API key: %w", err)
	}
	if err := validateDashScopeHTTPSURL(config.ManagementURL,
		"/api/v1/services/audio/tts/customization"); err != nil {
		return nil, fmt.Errorf("voice management endpoint: %w", err)
	}
	if err := validateDashScopeHTTPSURL(config.TTSURL,
		"/api/v1/services/aigc/multimodal-generation/generation"); err != nil {
		return nil, fmt.Errorf("voice TTS endpoint: %w", err)
	}
	publicURL, err := url.Parse(config.PublicHTTPSURL)
	if err != nil || publicURL.Scheme != "https" || publicURL.Host == "" ||
		publicURL.Path != "" || publicURL.RawQuery != "" ||
		publicURL.Fragment != "" || publicURL.User != nil {
		return nil, fmt.Errorf("public voice URL must be an exact HTTPS origin")
	}
	for name, value := range map[string]string{
		"target model": config.TargetModel, "voice prefix": config.VoicePrefix,
		"FFmpeg path": config.FFmpegPath, "profile file": config.ProfileFile,
	} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value ||
			strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("%s is invalid", name)
		}
	}
	if len(config.VoicePrefix) > 10 {
		return nil, fmt.Errorf("voice prefix is too long")
	}
	for _, character := range config.VoicePrefix {
		if !unicode.IsLetter(character) && !unicode.IsDigit(character) ||
			character > unicode.MaxASCII {
			return nil, fmt.Errorf("voice prefix must be ASCII alphanumeric")
		}
	}
	key, err := decodeMemoryKey(config.ProfileKey)
	if err != nil {
		return nil, fmt.Errorf("voice profile key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	clientCopy := *client
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = 5 * time.Minute
	}
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	service := &VoiceCloneService{
		config: config, client: &clientCopy, aead: aead,
		samples: make(map[string]*voiceSample),
	}
	if err := service.loadProfile(); err != nil {
		return nil, err
	}
	return service, nil
}

func (service *VoiceCloneService) RegisterHandlers(mux *http.ServeMux) {
	if service == nil || mux == nil {
		return
	}
	mux.HandleFunc("GET /voice", service.voicePage)
	mux.HandleFunc("POST /v1/voice/enrollment/authorize", service.authorizeEnrollment)
	mux.HandleFunc("POST /v1/voice/enrollment/{token}", service.uploadEnrollment)
	mux.HandleFunc("GET /v1/voice/sample/{token}", service.serveSample)
}

func (service *VoiceCloneService) BeginEnrollment() (string, error) {
	codeMaterial := make([]byte, 4)
	if _, err := rand.Read(codeMaterial); err != nil {
		return "", err
	}
	value := uint32(codeMaterial[0])<<24 | uint32(codeMaterial[1])<<16 |
		uint32(codeMaterial[2])<<8 | uint32(codeMaterial[3])
	code := fmt.Sprintf("%06d", value%1000000)
	service.mu.Lock()
	service.enrollment = voiceEnrollment{
		Code: code, ExpiresAt: time.Now().Add(voiceEnrollmentLifetime),
	}
	service.mu.Unlock()
	return code, nil
}

func (service *VoiceCloneService) Status() map[string]any {
	service.mu.Lock()
	defer service.mu.Unlock()
	return map[string]any{
		"configured": true, "active": service.profile.VoiceID != "",
		"selected": service.profile.Active, "model": service.profile.Model,
	}
}

func (service *VoiceCloneService) Activate(enabled bool) (bool, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.profile.VoiceID == "" {
		return false, nil
	}
	previous := service.profile.Active
	service.profile.Active = enabled
	if err := service.persistProfileLocked(); err != nil {
		service.profile.Active = previous
		return false, err
	}
	return true, nil
}

func (service *VoiceCloneService) Delete(ctx context.Context) (bool, error) {
	service.mu.Lock()
	profile := service.profile
	service.mu.Unlock()
	if profile.VoiceID == "" {
		return false, nil
	}
	payload, _ := json.Marshal(map[string]any{
		"model": "voice-enrollment",
		"input": map[string]any{
			"action": "delete_voice", "voice_id": profile.VoiceID,
		},
	})
	var response struct {
		Output map[string]any `json:"output"`
	}
	if err := service.postProviderJSON(ctx, service.config.ManagementURL,
		payload, &response); err != nil {
		return false, err
	}
	service.mu.Lock()
	previous := service.profile
	service.profile = voiceProfile{}
	if err := service.persistProfileLocked(); err != nil {
		service.profile = previous
		service.mu.Unlock()
		return false, err
	}
	service.mu.Unlock()
	return true, nil
}

func (service *VoiceCloneService) Synthesize(ctx context.Context,
	text string) ([][]byte, bool, error) {
	service.mu.Lock()
	profile := service.profile
	service.mu.Unlock()
	if profile.VoiceID == "" || !profile.Active {
		return nil, false, nil
	}
	pipeline := &CloudPipeline{
		ttsURL: service.config.TTSURL, ttsAPIKey: service.config.APIKey,
		ttsModel: profile.Model, ttsVoice: profile.VoiceID,
		ffmpegPath: service.config.FFmpegPath, httpClient: service.client,
	}
	packets, err := pipeline.Synthesize(ctx, text)
	return packets, true, err
}

func (service *VoiceCloneService) voicePage(writer http.ResponseWriter,
	_ *http.Request) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(writer, voiceEnrollmentHTML)
}

func (service *VoiceCloneService) authorizeEnrollment(writer http.ResponseWriter,
	request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, 2048)
	var input struct {
		Code    string `json:"code"`
		Consent bool   `json:"consent"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || !input.Consent || len(input.Code) != 6 {
		http.Error(writer, "無效的確認資料", http.StatusBadRequest)
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.enrollment.Code == "" || time.Now().After(service.enrollment.ExpiresAt) ||
		input.Code != service.enrollment.Code {
		http.Error(writer, "代碼已失效或不正確", http.StatusUnauthorized)
		return
	}
	token, err := randomConsentID()
	if err != nil {
		http.Error(writer, "暫時無法建立錄音", http.StatusInternalServerError)
		return
	}
	service.enrollment.Token = token
	service.enrollment.Code = ""
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(writer).Encode(map[string]string{
		"upload_url": "/v1/voice/enrollment/" + token,
	})
}

func (service *VoiceCloneService) uploadEnrollment(writer http.ResponseWriter,
	request *http.Request) {
	token := request.PathValue("token")
	service.mu.Lock()
	valid := token != "" && token == service.enrollment.Token &&
		time.Now().Before(service.enrollment.ExpiresAt)
	if valid {
		service.enrollment.Token = ""
	}
	service.mu.Unlock()
	if !valid {
		http.Error(writer, "錄音授權已失效", http.StatusUnauthorized)
		return
	}
	contentType := strings.Split(request.Header.Get("Content-Type"), ";")[0]
	if contentType != "audio/webm" && contentType != "audio/mp4" &&
		contentType != "audio/mpeg" && contentType != "audio/wav" &&
		contentType != "audio/x-wav" {
		http.Error(writer, "不支援這個錄音格式", http.StatusUnsupportedMediaType)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(writer, request.Body,
		maximumVoiceUpload))
	if err != nil || len(data) == 0 {
		http.Error(writer, "錄音資料無效", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Minute)
	defer cancel()
	wav, err := service.normalizeSample(ctx, data)
	if err != nil {
		http.Error(writer, "錄音太短、太長或無法辨識", http.StatusBadRequest)
		return
	}
	voiceID, err := service.createVoice(ctx, wav)
	for index := range wav {
		wav[index] = 0
	}
	if err != nil {
		http.Error(writer, "音色服務暫時無法完成註冊", http.StatusBadGateway)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"ok": true, "message": "音色已建立並啟用", "voice": voiceID != "",
	})
}

func (service *VoiceCloneService) normalizeSample(ctx context.Context,
	input []byte) ([]byte, error) {
	command := exec.CommandContext(ctx, service.config.FFmpegPath,
		"-hide_banner", "-loglevel", "error", "-i", "pipe:0",
		"-map", "0:a:0", "-ac", "1", "-ar", "24000", "-c:a", "pcm_s16le",
		"-f", "wav", "pipe:1")
	command.Stdin = bytes.NewReader(input)
	var output bytes.Buffer
	var errors bytes.Buffer
	command.Stdout = &output
	command.Stderr = &errors
	if err := command.Run(); err != nil || output.Len() > maximumVoiceSampleWAV+4096 {
		return nil, fmt.Errorf("normalize voice sample")
	}
	wav := output.Bytes()
	if len(wav) < minimumVoiceSampleWAV+44 || len(wav) > maximumVoiceSampleWAV+4096 ||
		len(wav) < 12 || string(wav[:4]) != "RIFF" || string(wav[8:12]) != "WAVE" {
		return nil, fmt.Errorf("voice sample duration is out of range")
	}
	return append([]byte(nil), wav...), nil
}

func (service *VoiceCloneService) createVoice(ctx context.Context,
	wav []byte) (string, error) {
	sampleToken, err := randomConsentID()
	if err != nil {
		return "", err
	}
	service.mu.Lock()
	service.samples[sampleToken] = &voiceSample{
		WAV: append([]byte(nil), wav...), ExpiresAt: time.Now().Add(2 * time.Minute),
	}
	service.mu.Unlock()
	defer func() {
		service.mu.Lock()
		if sample := service.samples[sampleToken]; sample != nil {
			for index := range sample.WAV {
				sample.WAV[index] = 0
			}
		}
		delete(service.samples, sampleToken)
		service.mu.Unlock()
	}()
	payload, _ := json.Marshal(map[string]any{
		"model": "voice-enrollment",
		"input": map[string]any{
			"action": "create_voice", "target_model": service.config.TargetModel,
			"prefix":         service.config.VoicePrefix,
			"url":            service.config.PublicHTTPSURL + "/v1/voice/sample/" + sampleToken,
			"language_hints": []string{"zh", "en"},
		},
	})
	var response struct {
		Output struct {
			VoiceID string `json:"voice_id"`
		} `json:"output"`
	}
	if err := service.postProviderJSON(ctx, service.config.ManagementURL,
		payload, &response); err != nil {
		return "", err
	}
	if response.Output.VoiceID == "" || len(response.Output.VoiceID) > 160 ||
		strings.IndexFunc(response.Output.VoiceID, unicode.IsSpace) >= 0 {
		return "", fmt.Errorf("voice provider returned an invalid ID")
	}
	service.mu.Lock()
	previous := service.profile
	service.profile = voiceProfile{
		VoiceID: response.Output.VoiceID, Model: service.config.TargetModel,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Active: true,
	}
	if err := service.persistProfileLocked(); err != nil {
		service.profile = previous
		service.mu.Unlock()
		return "", err
	}
	service.mu.Unlock()
	return response.Output.VoiceID, nil
}

func (service *VoiceCloneService) serveSample(writer http.ResponseWriter,
	request *http.Request) {
	token := request.PathValue("token")
	service.mu.Lock()
	sample := service.samples[token]
	if sample == nil || time.Now().After(sample.ExpiresAt) || sample.Fetches >= 3 {
		service.mu.Unlock()
		http.NotFound(writer, request)
		return
	}
	sample.Fetches++
	wav := append([]byte(nil), sample.WAV...)
	service.mu.Unlock()
	writer.Header().Set("Content-Type", "audio/wav")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Length", strconv.Itoa(len(wav)))
	_, _ = writer.Write(wav)
}

func (service *VoiceCloneService) postProviderJSON(ctx context.Context,
	endpoint string, payload []byte, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+service.config.APIKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := service.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("voice provider status %d", response.StatusCode)
	}
	return decodeLimitedJSON(response.Body, maxOpenRouterJSONBytes, output)
}

func (service *VoiceCloneService) loadProfile() error {
	data, err := os.ReadFile(service.config.ProfileFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read encrypted voice profile: %w", err)
	}
	if len(data) < len(voiceProfileHeader)+service.aead.NonceSize() ||
		string(data[:len(voiceProfileHeader)]) != voiceProfileHeader {
		return fmt.Errorf("encrypted voice profile has an invalid format")
	}
	nonceStart := len(voiceProfileHeader)
	nonceEnd := nonceStart + service.aead.NonceSize()
	plain, err := service.aead.Open(nil, data[nonceStart:nonceEnd],
		data[nonceEnd:], []byte(voiceProfileHeader))
	if err != nil || json.Unmarshal(plain, &service.profile) != nil {
		return fmt.Errorf("authenticate encrypted voice profile")
	}
	if service.profile.VoiceID == "" || service.profile.Model != service.config.TargetModel {
		return fmt.Errorf("encrypted voice profile content is invalid")
	}
	return nil
}

func (service *VoiceCloneService) persistProfileLocked() error {
	if service.profile.VoiceID == "" {
		err := os.Remove(service.config.ProfileFile)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	plain, err := json.Marshal(service.profile)
	if err != nil {
		return err
	}
	nonce := make([]byte, service.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	data := append([]byte(voiceProfileHeader), nonce...)
	data = service.aead.Seal(data, nonce, plain, []byte(voiceProfileHeader))
	directory := filepath.Dir(service.config.ProfileFile)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".voice-profile-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, service.config.ProfileFile)
}

const voiceEnrollmentHTML = `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>建立我的 Agent 音色</title><style>:root{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#edf7f2;background:#07130f}body{margin:0;padding:24px}main{max-width:620px;margin:auto;background:#10231d;border:1px solid #285746;border-radius:18px;padding:24px}h1{margin-top:0}p{color:#b7cec4;line-height:1.55}input[type=text]{box-sizing:border-box;width:100%;font-size:28px;letter-spacing:8px;padding:14px;border-radius:10px;border:1px solid #46715f;background:#07130f;color:white;text-align:center}label{display:block;margin:20px 0;line-height:1.5}button{width:100%;padding:15px;border:0;border-radius:11px;background:#51d99a;color:#062016;font-size:18px;font-weight:700}button:disabled{opacity:.45}.status{margin-top:18px;padding:14px;border-radius:10px;background:#172e26}.warn{color:#ffd476}</style></head><body><main><h1>建立我的 Agent 音色</h1><p>先對裝置說「建立我的音色」，並在裝置上按 BOOT 核准。接著輸入裝置讀出的六位數代碼。</p><input id="code" type="text" inputmode="numeric" maxlength="6" placeholder="000000"><label><input id="consent" type="checkbox"> 我確認這是我本人的聲音，並同意用它建立這台裝置的合成音色。</label><button id="record">錄製 15 秒聲音樣本</button><div class="status" id="status">請在安靜環境，以自然音量連續說話。</div><p class="warn">請勿克隆未經本人授權的聲音。錄音樣本只用於本次註冊，完成後會立即從 Gateway 記憶體清除。</p></main><script>const b=document.getElementById('record'),s=document.getElementById('status');b.onclick=async()=>{try{if(!document.getElementById('consent').checked)throw Error('請先勾選本人同意');const code=document.getElementById('code').value;if(!/^\d{6}$/.test(code))throw Error('請輸入六位數代碼');b.disabled=true;s.textContent='正在取得麥克風…';const stream=await navigator.mediaDevices.getUserMedia({audio:{channelCount:1,echoCancellation:true,noiseSuppression:true}});const chunks=[],r=new MediaRecorder(stream);r.ondataavailable=e=>{if(e.data.size)chunks.push(e.data)};r.start();for(let n=15;n>0;n--){s.textContent='請自然朗讀，剩下 '+n+' 秒';await new Promise(x=>setTimeout(x,1000))}r.stop();await new Promise(x=>r.onstop=x);stream.getTracks().forEach(t=>t.stop());s.textContent='正在安全建立音色…';const a=await fetch('/v1/voice/enrollment/authorize',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code,consent:true})});if(!a.ok)throw Error(await a.text());const j=await a.json(),blob=new Blob(chunks,{type:r.mimeType});const u=await fetch(j.upload_url,{method:'POST',headers:{'Content-Type':blob.type},body:blob});if(!u.ok)throw Error(await u.text());const done=await u.json();s.textContent=done.message+'。現在下一次回覆會使用新音色。'}catch(e){s.textContent=e.message||'建立失敗，請重試'}finally{b.disabled=false}};</script></body></html>`
