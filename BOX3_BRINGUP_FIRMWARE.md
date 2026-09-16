# ESP32-S3-BOX-3 可實測韌體

這是第一個可直接燒入未改裝 ESP32-S3-BOX-3 的開發版韌體。它不要求工廠
eFuse、雲端服務或 API key，也不會寫入 eFuse。

## 可以驗證什麼

- ESP32-S3、16 MB Flash、8 MB PSRAM 是否符合板型設定；
- ES8311 喇叭、ES7210 麥克風與 I2S/TDM 是否能初始化及傳輸資料；
- 開機播放約 240 ms 的測試音，之後取樣麥克風並輸出 peak/mean 數值；
- 真正的 ESP-Claw typed capability registry；
- 短按 BOOT 後，以一次性實體同意執行
  `device.set_indicator({"on": true|false})`；
- `device.get_status({})` 回報音訊與指示燈狀態。

這些是板級 bring-up 證據，不代表聲學品質、雲端語音或量產資格通過。

## 建置與燒錄

```sh
cd outputs/xiaozhi-agent-platform
./tools/build_box3_bringup.sh
./tools/flash_box3_bringup.sh /dev/cu.<你的裝置> monitor
```

建置腳本會優先使用已啟用的 ESP-IDF 6.0.2；在目前工作區也能自動使用
釘選的本機工具鏈。建置後的單一燒錄映像位於
`dist/box3-bringup/box3-bringup-0.15.0.bin`，從位址 `0x0` 燒錄。

若不需要立即開啟序列終端，可省略最後的 `monitor`。終端中按 `Ctrl+]`
離開監看。

> 燒錄會覆寫板上既有的 bootloader、分割表、NVS 與第一個 App 區域。如需
> 保留原廠資料，先備份整片 Flash。這個韌體不會寫入 eFuse。

## 板上操作

1. 開機後背光會短閃，喇叭播放短音，序列終端應出現兩個 `[PASS]`。
2. 對著麥克風說話，再按住 BOOT 約 1.5 秒後放開；韌體會重跑音訊測試，
   新的 `mic_peak` 與 `mic_mean_abs` 應跟安靜環境不同。
3. 短按 BOOT，背光會透過 ESP-Claw `device.set_indicator` 切換；終端應顯示
   `decision=0`、`result=ESP_OK` 與 `[PASS]`。

預期的關鍵紀錄：

```text
[PASS] audio codec/I2S I/O; mic_peak=... mic_mean_abs=...
[PASS] ESP-Claw device.get_status => {"profile":"box3-bringup",...}
[PASS] physical-consent ESP-Claw device.set_indicator => {"ok":true}
```

## 邊界

- 不連 Wi-Fi，也不連 XiaoZhi/LLM gateway；這一版先把實體板與 Agent tool
  執行鏈變成可重複測試的基線。
- 不得將此映像出貨；它明確使用開發用 plaintext NVS 並跳過工廠身分。
- 下一版會在這個真機基線上加入開發用配網與受控的語音 gateway 測試。
