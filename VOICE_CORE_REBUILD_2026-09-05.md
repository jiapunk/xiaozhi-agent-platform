# 語音核心重構與部署紀錄 — 2026-09-05

## 狀態

已實作、測試、部署；尚待使用者實際語音辨識與插話驗收。不能把編譯／健康檢查通過等同於辨識問題完全解決。

- 手錶啟動確認 `2.4.3-voice-core1`，ELF SHA256 `2a6e78c7075e25120719b6ed81b72cc7153fbecb7e51239741811b8b78daf37b`。
- 只寫入 `ota_0` 程式分區，位址 `0x200000`；esptool 驗證寫入雜湊成功。未清除 NVS、Wi-Fi、資產字庫或個人設定。
- Japan Gateway 已原子替換並重新啟動 `xiaozhi-gateway`；未修改服務環境、模型、API 金鑰、記憶、Caddy 或 Xray。
- 實機已取得 Gateway hello、同步時間，並回報 voice transport ready。公開 HTTPS `/healthz` 返回成功；此檢查本身不驗證 API 額度或辨識品質。

## 重構內容

### 手錶

1. 喚醒／觸控開始即建立收音；提示音、TLS 連線不再先關閉麥克風再等待。保留有限長度的待送語音，超出容量明確停止並要求重試，不悄悄刪句首。
2. 單一 transport worker 序列化連線、控制訊息與音訊傳送；UI 主迴圈不再直接等待網路寫入。背景預連線與使用者連線共用同一個工作，不建立競爭連線。
3. 對話內維持同一收音／AEC／輸入增益設定；說話與聆聽的畫面切換不重啟 Opus／AFE 或重送 listen/start。
4. 收音、重採樣、編碼及上行佇列失敗會鎖定不完整串流。舊 generation 的編碼結果無法回灌新問題。
5. 修正 AFE 重啟等待與首段 PCM 被 reset 清除。Opus AUDIO 模式關閉不相容的 DTX，連續送音，不以 VAD 切掉低音量片段。
6. 收音開始前無聲開啟 DAC，對話內持有輸出配置，避免睡屏或開始回答時重新配置共用 I2S；收音結束釋放持有，保留待機省電。
7. 網路回呼與 UI 排程加入世代隔離。舊連線成功／失敗／取消不能套到新一輪。接收中斷時同步清除舊播放，避免延後清除誤刪新回答開頭。
8. 分開 VAD 邊緣通知與持續對話活動。初始靜音 30 秒、真正停滯 120 秒才結束；持續說話不受固定錄音上限截斷，keepalive 不延長停滯期限。
9. 新增 raw MIC、REF、post-AFE 的數值品質診斷及播放 I/O 錯誤。只計算 RMS、peak、clipping、zero frames、間隔、數量，不保存原始錄音。

### Gateway

1. 裝置事件 → decoder、decoder → provider、provider → encoder 分成有界 FIFO。慢 API、FFmpeg 或播放不再堵住主要收包及插話事件。
2. 保持 PCM 順序；audio.done 是與音訊同列的 finish barrier，等前段資料全處理後才 flush/drain。
3. 回答與輸入採 generation 隔離。新問題在搜尋／思考期間亦取消舊工具工作；舊 encoder 取消不會誤殺新 session。
4. TTS 控制使用 session lifetime context；close 先取消再取鎖，避免被阻塞的網路寫入卡住關閉。
5. 佇列溢位明確回報 `audio_input_overflow`／`audio_output_overflow`，不無聲丟音。記錄排隊高水位、等待、完成／失敗／過期計數及裝置 `output_errors`。

## 驗證

- 正式 watch build helper 通過；應用程式 3,152,944 bytes，4 MiB 分區尚餘約 25%。
- 韌體建置工具 71 項 Python 測試通過。
- PCM 統計／串流世代與 session timeout 的 host 測試，以 `-Werror`、ASan、UBSan 通過；含全部 65,536 種 PCM16 常值 RMS 邊界。
- Gateway `go test ./...`、`go vet ./internal/s3camdev` 通過。
- Gateway race 測試連續 3 次通過；新增 11 項回歸，包含慢連線不阻塞 MCP／不丟句首、取消舊 flush、多輪 PCM 順序，以及下游完全堵住時仍處理插話。
- 測試中的小於 250 ms 是本機模擬 provider 事件處理，不是手錶到雲端的實際打斷延遲保證。
- 首次 build 曾因新增診斷標頭洩漏 `<cmath>`，與板級 vendor 的 `M_PI` 巨集衝突；已改為有界整數 RMS，不修改 vendor，重建通過。

## 發布與回復

本機檔案位於 `work/release-voice-core1-20260905/`，韌體含既有開發配置，維持私人檔案權限，勿直接公開發佈。

| 產物 | SHA256 |
| --- | --- |
| xiaozhi.bin | `c360132fb0ba3eb1cdb03568a0b35ca76bcf5a7d0fd6e73d71cfd5a7b658c3a8` |
| s3camdevgateway | `5a541c80e91c3fbd16dc1f6ad80e0a676f0d351f280f5ef7acc2bddd96493200` |

舊手錶程式及 application 來源備份：`work/watch-backups/core-rebuild-20260905.3z24vK/`。

Japan 舊 Gateway 備份：`/opt/xiaozhi-gateway/releases/voice-core1-20260905/s3camdevgateway.previous`，旧 SHA256 `478b7146dea67ecc70d5a24e417642ee2aa233fa9eab796b13db3a780f74752d`。

## 尚未完成的驗收

- 一般佩戴距離：喚醒直接接問題，不能漏掉句首。
- 連續至少 10 輪正確辨識、回答，不自動重新連線、不被舊事件打回待命。
- 回答中插話改問，應保留「等等」後的新問題，而非只停止舊回答。
- 比較 raw MIC 與 post-AFE 的 clipping、零幀及實際辨識；尚未取得足夠實機雙講樣本，不能宣稱 AEC 聲學校準完成。
- 啟動成功音的 standby 27 dB 窗口曾出現 MIC 削波 170／48,000 取樣；後續安靜待機窗口為零。這不是 conversation 24 dB 的校準資料，不能直接據此調增益。raw 與 post-AFE 窗口不同步，不能直接計算回音消除量。
- 本次未重新測量電池续航；DAC hold 僅在收音期間生效，但仍需離線佩戴驗證。
