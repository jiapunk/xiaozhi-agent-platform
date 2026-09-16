# International Individual-Developer Kit Launch

## 定位結論

「國際個人開發者」在交易與 App 政策上是單一使用者／消費者，不是由企業為員工或學生
採購的 managed organization。因此首發候選路線改為 **Lane B：Direct Consumer Hardware
+ Cloud**，SKU 維持 `VOICE_AGENT_KIT_BOX3`：官網販售硬體與 Voice／Agent cloud plan，
以公開免費 Companion App 完成配網、登入、裝置管理與既有權益使用。

這是 revision 2 的 `PROPOSED` rollout，不是上市批准。App 內不提供購買，也不放置導往
外部付款的按鈕或文案；web checkout 的已驗證 billing lifecycle 經 provider adapter 才能
更新 entitlement。若法律或 store review 認定某市場不容許此模型，該市場必須改用經批准
的 region-specific profile，不能靜默改變 App 行為。

## 市場分批

「International」不是一個法規區域。Wave 1 是六個候選市場的工作包，只有該列全部證據
完成並寫入 `legal_market` WORM evidence 後，該市場才可由 `PROPOSED` 進入正式批准。

| 候選市場 | 語言基線 | 發售前最低外部證據 | 官方入口 |
|---|---|---|---|
| AU | English | 適用 standards／testing、supplier statement and records、responsible-supplier registration、RCM label；確認 final host／antenna／power | [ACMA supplier obligations](https://www.acma.gov.au/know-what-you-must-do), [ACMA RCM labelling](https://www.acma.gov.au/step-5-label-your-product) |
| CA | English | ISED 適用 RSS／certification、Canadian representative／listing、label 與 user notice 結論 | [ISED RSS-Gen](https://ised-isde.canada.ca/site/spectrum-management-telecommunications/en/devices-and-equipment/radio-equipment-standards/radio-standards-specifications-rss/rss-gen-general-requirements-compliance-radio-apparatus) |
| GB | English | Radio Equipment Regulations 的 conformity assessment、technical documentation、declaration、marking／economic-operator 結論 | [UK Radio Equipment Regulations](https://www.gov.uk/government/publications/radio-equipment-regulations-2017/radio-equipment-regulations-2017-great-britain) |
| SG | English | 由適格 supplier 完成適用 equipment registration、label／dealer obligations 結論 | [IMDA Equipment Registration](https://iris.imda.gov.sg/guide/equipment-registration-guide) |
| TW | 繁體中文／English | NCC 適用審驗類型、申請人／進口、標示、中文說明與 final-host 結論 | [台灣 NCC 審驗辦法](https://ncclaw.ncc.gov.tw/FLAW/PrintFLAWDAT0202.aspx?id=FL012813) |
| US | English | FCC equipment authorization／grantee 或 module-integration path、label／manual、antenna／RF exposure 與 final-host 結論 | [FCC Equipment Authorization](https://opendata.fcc.gov/Engineering-Technology/EAS-Equipment-Authorization-Grantee-Registrations/3b3k-34jp) |

Wave 2 才評估 EU／EEA、日本、韓國等市場。EU 除 RED conformity 外還要在正式 scope 中
確認適用的 cybersecurity、privacy、environmental、consumer、tax、language 與
economic-operator 義務；日本與韓國則先取得當地 RF／telecom、標示與進口法律結論。
[EU Radio Equipment Directive](https://single-market-economy.ec.europa.eu/sectors/electrical-and-electronic-engineering-industries-eei/radio-equipment-directive-red_en)

採用已認證 ESP32 module 可能縮小部分測試範圍，但不能從 module 證書推論整機、天線、
電源、外殼、軟體或標示已合規。六個 Wave 1 市場目前全部是 **NO-GO pending evidence**。

## Companion App 契約

- iOS：`public_free_companion`。App 只做配網、登入、裝置控制、權益狀態顯示與既有
  Voice／Agent service 使用；沒有 App 內購買、價格、方案選擇、外部付款連結或購買 CTA。
- Android：`public_consumption_only`，與 iOS 使用相同產品邊界。任何 region-specific
  alternative billing／external-offer program 都必須先變更 launch profile 並重新審查。
- App 不把硬體訂單、checkout return URL 或 client callback 當成 entitlement authority。
- App 顯示 `active`、`grace`、`suspended`、`ended` 與可恢復錯誤，不自行延長權益。
- 若使用者沒有 entitlement，App 可說明服務不可用與提供一般支援資訊，但首發 profile
  不在 App 內引導購買。

Apple 對 App 內數位功能通常要求 IAP；免費 standalone companion 的適用條件包含 App 內
不得購買或呼叫外部購買。Enterprise exception 不適用 consumer／single-user／family。
[Apple App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/)
Google Play 對 App 內數位／cloud service 一般要求 Play Billing，consumption-only 路徑及
地區 program 必須依當期規則審查。
[Google Play Payments policy](https://support.google.com/googleplay/android-developer/answer/9858738)

## 商業與帳戶邊界

官網 checkout 可以包含實體硬體與獨立列示的 Voice／Agent 週期方案，但 billing provider
原始事件先由 web billing adapter 驗證並向 provider API re-fetch，才能產生 M84 canonical
signed entitlement update。Account 只由正式 IdP／account ownership flow 建立；付款成功
不自動建立、合併或改綁帳戶。

供應商選型必須逐項通過：

- merchant entity 與 Wave 1 國家支援；
- 同時處理 physical goods、recurring digital service 與分開退款的能力；
- tax calculation／registration／invoice export、multi-currency、SCA／3DS；
- provider-native signed webhook、API re-fetch、event ordering、reconciliation export；
- cancel-at-period-end、partial/full refund、chargeback／dispute 與客服 audit；
- data residency、subprocessors、retention、breach／DPA 與 legal review；
- HSM／KMS signer、mTLS、least privilege、test/live tenant separation 與 WORM export。

目前 billing provider、merchant legal entity、IdP、HSM／KMS、SDK distribution owner、
legal reviewer 與 decision owner 均為 `UNSELECTED`。任何候選供應商都不是本文件的採購決定。

## Machine-readable profile

候選設定位於
`release/product-launch-decision.international-developer-proposed.json`。它固定 Lane B、六個
排序 market codes、direct web checkout、免費／consumption-only App 與 web billing
adapter；provider／authority 仍未選定，approval times 為零，所以 production
`--require-approved` 必須失敗。

Validator 只證明 market code 是兩個大寫字母的 closed shape；是否為真正 ISO 3166-1
市場、是否適合上市，仍由 `legal_market` authority 驗證。即使未批准的 profile，也不得
包含與所選 lane 矛盾的 channel 組合。

> 法規與平台政策內容是工程風險邊界，不構成法律意見；發布日仍須重新查核官方規則。
