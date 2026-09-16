# 手錶接回後基準驗證 — 2026-09-05

本輪只做診斷，未修改韌體或 Gateway、未清除 Wi-Fi／個人設定、未充值。

## 裝置與連線

- USB 出現 `/dev/cu.usbmodem2101`，可讀取 ESP32-S3 啟動與即時序列紀錄。
- 啟動顯示：版本 `2.4.2`，編譯時間 `Aug 30 2026 06:21:54`，ELF SHA 前綴 `2420618d6`。
- 本地既有 ELF 的 SHA256 為 `2420618d606814f4336296bc5d256ab476f6b7ee4c3bb8d04d5c85b103a353b2`，版本與編譯時間一致。沒有讀回整個 Flash，因此這是版本／前綴比對，不是完整 Flash hash 驗證。
- 日本 `/status` 回報裝置已連線，MCP 狀態工具成功。
- 序列觀察開啟後兩次讀到 USB_UART_CHIP_RESET 啟動紀錄；未發送主動 reset 命令，但不能把開關序列埠視為完全無重啟副作用。後續應保留同一序列連線，避免干擾基準。

## 使用者測試

請使用者說「你好星辰，現在可以聽到我嗎？」；使用者回報沒有聽到回答。

手錶單次開機相對時間：

| 時間 | 觀察 |
|---|---|
| 112200 ms | 喚醒詞匹配，prob=0.108095 |
| 112210 ms | Idle → Connecting |
| 112250 ms | Connecting → Listening |
| 113050 ms | post-AEC voice activity started |
| 113270 ms | post-AEC voice activity stopped |
| 113910 ms | 第二次 post-AEC voice activity started |
| 114960 ms | 第二次 post-AEC voice activity stopped |
| 115830 ms | realtime_unavailable，準備重設語音通道 |
| 123320 ms | 收音 watchdog：10905 ms，speech=no；Listening → Idle |

可以確認本輪喚醒與收音活動存在。從匹配到 Listening 狀態約 50 ms；這不是從使用者開始說喚醒詞起算的延遲，也不代表雲端已準備好。未取得成功轉錄，不能宣稱問題已被完整辨識。

## 日本 Gateway 同步證據

2026-09-05 16:43:44.252 UTC：OpenAI Realtime session connected，model=gpt-realtime-2.1。

2026-09-05 16:43:44.253 UTC：session failed：

`type=insufficient_quota code=credit_balance_exhausted`

上游明確表示沒有剩餘 credits，需補充 API 額度。

因此這次「沒有回答」的直接阻塞原因是 API 額度耗盡，不是未喚醒，也沒有證據指向本輪喇叭播放失敗。

雖然可見已發生 VAD 事件、稍後 watchdog 卻記錄 speech=no，但上游錯誤先發生，不能將本輪當成「正常長問題被 watchdog 截斷」的獨立重現。額度恢復後仍需另外測長句、多輪與插話。

## 下一步

1. 使用者確認目前 API key 所屬組織／專案的計費額度恢復。
2. 再驗證一次最短語音問答，再進行 15–20 秒長句與多輪插話。
3. 依原審閱結果修正核心缺陷；充值不會自動修好已發現的程式問題。

未保存語音內容、帳號金鑰或個人化記憶到本報告。序列觀察已結束，SSH 已登出。

## 補充：充值後短問答（2026-09-05 16:50 UTC）

使用者確認完成付款後，再次進行基準測試。未變更模型、韌體、Gateway 或個人設定。新一次序列監看讀到同版本啟動紀錄。

### 額度與播放恢復已確認

- 16:50:36.437 UTC：建立新的 `gpt-realtime-2.1` session。
- 同一測試窗口有實際輸入 PCM、模型字幕、`watch_get_status` 工具成功完成。
- 16:50:51.389 UTC：收到 `device playback drained`，wait_ms=801；不是僅靠 completed_turns 推斷。
- 裝置完整性報告：received_packets=162、played_packets=163、dropped_packets=0、decode_errors=0、playback_underruns=0。兩項封包數的計數範圍尚未釐清，不能將其直接視為逐封包完全一致的證明。
- 此窗口沒有新 session failed 或 credit_balance_exhausted。
- 使用者明確表示「有喚醒、辨識錯誤、也有回答」。

因此本輪可以確認上游額度阻塞已解除、語音回答有實際播放，不能宣稱辨識與交互已恢復正常。

### 辨識／回答錯誤與收音空窗

本次指定的非敏感測試句是「一加一等於多少」。手錶顯示的輸入辨識結果與該句不符，模型則調用手錶狀態並回答時間。使用者確認辨識錯誤。

韌體目前流程為：

1. `BeginWakeWordInvoke` 關閉語音處理。
2. 先進入 Listening 並更新畫面。
3. 播放本地提示音，期間語音處理仍關閉。
4. 等 PlaybackDrained 才 `StartListeningAudio`；先送 listen/start，再開啟語音處理。
5. 此路徑的 pending_wake_audio_upload=false，因此不補送喚醒後問題前綴。

本地提示音約 0.49 秒。也就是畫面已表示「聆聽」，實際仍有尚未處理問題語音的空窗；緊接喚醒詞的短問題可能丟失首段。這是程式中可確認的流程缺口，但是否單獨造成此次錯誤，尚待對照。

已請使用者改用輕觸進入聆聽、等待約一秒，再單獨說相同測試句；此舉僅用於定位，不是長期操作方案。

另須注意：native Realtime 的語音理解與字幕轉錄是不同流程；`handleInputTranscript` 在 TranscriptFirst=false 下不拿字幕重新提問，因此字幕和回答不一致，不代表 Gateway 把字幕原文送去作為文字問題。

唯讀本地 `TestRealtimeOpusDecoderEmitsPCMBeforeInputCloses` 通過，前兩個 60 ms 封包可產生 PCM。目前沒有證據指向 FFmpeg 固定吞掉本輪問題首音。

### 新觀察：回答後上行失敗並重連

手錶開機相對時間 82380 ms：Speaking → Listening；87950 ms：`Audio upload stalled; rebuilding voice channel`；88190 ms 回 Idle 並開始預連線，91890 ms ready。

這發生於回到 Listening 後約 5.6 秒，不是 10 秒收音 watchdog。該訊息僅表示 `SendAudio` 返回 false，可能是 socket 已斷、TLS 寫入錯誤或發送逾時，不能單憑這一行判定是麥克風、網路品質或 CPU 不足。當前處理還會直接清掉整個待送佇列，後續問題前段因此有再次遺失的風險。

需補獨立 socket 寫入時間／errno 與音訊序號，才能定位來源；不能把此次上行失敗說成已修好。
