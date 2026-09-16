# Product SKU Porting Guide

## 目的

這份指南用於把同一套小智語音＋ESP-Claw Agent 產品骨架移植到新的 ESP32 系列產品。
原則是新增產品差異層，而不是複製整個應用或修改上游內部實作。

## 新增一個 SKU 的必要工作

1. **凍結產品定義**
   - 指定不可重用的 SKU、board ID、hardware revision 與 lifecycle。
   - 固定 SoC、最低／精確 Flash、PSRAM、partition、供電與外部周邊。
   - 明列 audio input/output、display、實體 presence input 及其極性／時間門檻。
   - 對每個 Agent capability 分成 read 與 state-changing action；預設全部拒絕。

2. **建立 board component**
   - 實作唯一的 Codec、I2S/TDM、GPIO、display 與 power owner。
   - 從小智選擇性移植已驗證的 board/audio 模組，不引入完整 app、Wi-Fi manager、
     OTA、filesystem 或第二套生命週期。
   - 保持 ESP-Claw 只透過產品 adapter 取得 capability，不直接取得任意硬體或 shell。

3. **加入 SKU profile 與組態閘門**
   - 在 `product_sku_core` 新增固定 profile 與 host observation matrix。
   - 在 Kconfig 新增 board/SKU choice 和 hardware revision。
   - 在 CMake 建立 board↔SKU、Live runtime、production-security 與 partition 的
     fail-closed 配對；不可用名稱或預設值繞過。

4. **建立可讀硬體與工廠身分驗證**
   - 啟動最前段核對 SoC revision、Flash 與 PSRAM。
   - 為候選 SKU 指定獨立、不可讀寫且 purpose 鎖定的 eFuse HMAC key；以裝置綁定
     manifest 核對 SKU、board contract、hardware/silicon revision、base MAC、
     registry record version 與唯一 manifest ID。
   - manifest 必須在 storage 後、reset recovery／network 前驗證；正常產品 API 只可
     驗證，不可簽署、寫入或清除工廠身分。
   - 恢復原廠不得清除 manifest；不得將 authenticated/reset-stable 誇稱成 manifest
     本體硬體不可變。若需撤銷同機舊 record，必須有可信 record floor 或單調狀態。
   - 不得把相同 SoC／memory geometry 當成板型證據。

5. **建立專用建置與供應鏈證據**
   - 新增 partition table、sdkconfig defaults、Live compile 與 production-security gate。
   - 重跑 linker-map internal/DMA/PSRAM 預算、App/bootloader signing、SBOM/map/license、
     OTA target 與 release subject。
   - 每個 SKU 的映像、SBOM、OTA、factory receipt 與市場 evidence 必須綁相同 subject。

6. **做真機 qualification**
   - 驗證錯板、錯 revision、錯 Flash／PSRAM、缺周邊、缺 eFuse、錯 partition 均停止啟動。
   - 驗證 Wi-Fi／配網、長按、reset、Secure Boot、Flash Encryption、OTA rollback、
     power-cut、音訊 capture/playback、AEC、聲學、熱、功耗與 8 小時以上 soak。
   - 使用犧牲板測試不可逆 eFuse 流程，不能以 virtual eFuse 取代量產證據。

7. **逐能力放行**
   - 新 SKU 初始只允許可觀測、無狀態副作用的 read capability。
   - 每個 action 需具備 exact typed argument、owner/session/request 綁定 consent、
     一次性 grant、執行時二次 policy check、metadata-only audit 與真硬體驗證。

## 必須拒絕的捷徑

- 只改 board 名稱但沿用另一 SKU 的 GPIO、HMAC slot、manifest、partition 或 factory receipt。
- 依 Flash／PSRAM 猜測板型或硬體 revision。
- 直接打開 ESP-Claw filesystem、shell、HTTP、MCP、Lua 或上游完整 skill 集。
- 讓開發 reference profile 啟動 Live runtime 或進入 production-security build。
- 把 compile/link、fixture、mock provider 或 host tests 寫成真機／量產／上市 PASS。

## 完成定義

一個新 SKU 只有在軟體組態、可讀硬體、eFuse-backed 工廠認證身分、真機資格、供應鏈、OTA、
服務端 subject 與市場 evidence 全部交叉綁定後，才可交給 release authority 評估。
沒有完整 `MARKET_RELEASE_PASS` 就不能以本指南或任何單項測試宣稱可出貨。
