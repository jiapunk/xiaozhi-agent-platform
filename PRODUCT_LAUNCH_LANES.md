# Product Launch Lanes

## 建議結論

使用者已將首發客群定義為「國際個人開發者」，因此目前建議改採 **Lane B：Direct
Consumer Hardware + Cloud Developer Kit**，對應既有 `VOICE_AGENT_KIT_BOX3` SKU。
個人開發者是 single-user／consumer transaction，不具備 Lane A 直接售予組織並供其員工
或學生使用的 enterprise 條件。

Revision 2 仍是 `PROPOSED`，不是市場批准。Wave 1 候選市場為 AU／CA／GB／SG／TW／US；
付款 provider、merchant legal entity、IdP、HSM／KMS、正式 SDK distribution、法律審查、
App review 與各市場 RF evidence 尚未選定或取得，所以仍是 NO-GO，不得產生
`MARKET_RELEASE_PASS`。完整 rollout 見
[International Individual-Developer Kit Launch](INTERNATIONAL_DEVELOPER_KIT_LAUNCH.md)。

## 三條路線比較

| Lane | 首發客戶與交易 | Companion App | Entitlement 來源 | 相對風險 |
|---|---|---|---|---|
| Lane A — Developer/System Integrator Kit（開發者／系統整合商） | 直接對組織報價、合約、invoice；硬體與受控 Voice／Agent service | 企業 custom/private app，或經法律／store review 的免費 provisioning companion | contract/invoice adapter | 最低；但不符合已選定的個人開發者交易。 |
| Lane B — Direct Consumer Hardware + Cloud（目前建議） | 官網硬體銷售加 web cloud subscription | 免費 consumption-only／hardware companion；App 內不得購買或導往外部付款 | web billing adapter，部分市場可能需另行核准的 store-specific path | 中高；符合個人開發者，但退款、稅、消保、App 規則與客服增加。 |
| Lane C — Consumer Mobile Subscription | App 內直接購買 Voice／Agent subscription | public App Store／Google Play billing | Apple／Google billing adapters，加 region-specific alternatives | 最高；雙 store lifecycle、費率、family／refund、兒童與大眾隱私要求。 |

不要把三條路線同時做成首版。它們不是同一個 billing adapter 的 UI 差異，而是不同的銷售
契約、退款權責、App 審核、entitlement ordering、客群支援與法規 evidence。

## 平台規則對架構的影響

Apple 目前要求 App 內解鎖數位功能通常使用 In-App Purchase，但明列 enterprise services、
免費 standalone companion 與部分 hardware-specific functionality 的例外條件。Enterprise
例外只涵蓋直接售予組織供其員工／學生使用；consumer／single-user／family sales 仍須依
IAP 規則。免費 web-tool companion 必須沒有 App 內購買或外部購買 call-to-action。
[Apple App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/)

Google Play 對 App 內數位功能／cloud service 一般要求 Play Billing，實體商品例外不會
自動涵蓋隨硬體銷售的數位服務；各地 alternative billing／external links 另有 program。
Consumption-only App 可以讓既有客戶登入，但不可在 App 內購買。政策會依地區更新，不能用
單一全球假設。
[Google Play Payments policy](https://support.google.com/googleplay/android-developer/answer/9858738)

Lane A 可用 Apple Business Manager 的 private Custom App 指定組織；distribution method
核准後不能直接在 public/private 之間切換。Android 可用 Managed Google Play 對指定企業
發布 custom/private app，但客戶通常需要 EMM／managed organization。若目標客戶多為個人
開發者而非有 IT 管理的公司，免費 public／unlisted companion 可能較可行，但必須先取得
store 與法律結論。
[Apple distribution methods](https://developer.apple.com/help/app-store-connect/manage-your-apps-availability/set-distribution-methods),
[Managed Google Play enterprise publishing](https://support.google.com/googleplay/work/answer/10637198)

Lane B 的 billing provider 仍未選定。選型必須同時涵蓋實體硬體、週期數位 service、稅、
退款／chargeback、原生簽章事件、API re-fetch、reconciliation 與 Wave 1 merchant entity，
不能因單一 checkout demo 成功就決定供應商。事件到產品權益的固定邊界見
[Web Billing Adapter Contract](WEB_BILLING_ADAPTER_CONTRACT.md)。

## 市場法規入口

ESP32 Wi-Fi／Bluetooth kit 不是「開發板」名稱就能免除上市要求。美國 FCC 說明受管制 RF
device 在輸入或 marketing 前須完成適用 equipment authorization；歐盟 RED 對 radio
equipment 的安全／健康、EMC、頻譜及部分隱私／防詐提出 essential requirements；台灣 NCC
的販賣用射頻器材則依用途進行型式認證、符合性聲明、簡易符合性聲明或逐部審驗。採用已認證
module 可能降低測試範圍，但 final host、天線、電源、外殼、標示與軟體更新仍需由合格實驗室／
法律顧問確認，不能從本機 source 推論合規。
[FCC Equipment Authorization](https://opendata.fcc.gov/Engineering-Technology/EAS-Equipment-Authorization-Grantee-Registrations/3b3k-34jp),
[EU Radio Equipment Directive](https://single-market-economy.ec.europa.eu/sectors/electrical-and-electronic-engineering-industries-eei/radio-equipment-directive-red_en),
[台灣 NCC 審驗辦法](https://ncclaw.ncc.gov.tw/FLAW/PrintFLAWDAT0202.aspx?id=FL012813)

AU／CA／GB／SG／TW／US 六個 Wave 1 候選市場的官方入口與逐市場 evidence checklist 見
[International Individual-Developer Kit Launch](INTERNATIONAL_DEVELOPER_KIT_LAUNCH.md)。六個
市場目前都未獲放行；「international」不等於一份全球合規結論。

## Machine-readable 決策

目前選定客群的提案在
`release/product-launch-decision.international-developer-proposed.json`，已固定：

- Lane B 與 `target_markets: ["AU","CA","GB","SG","TW","US"]`；
- `direct_web_checkout`、`public_free_companion`、`public_consumption_only`；
- `web_billing_adapter`；
- billing／IdP／SDK distribution／legal review／decision owner 為 `UNSELECTED`；
- approval timestamps 為零。

`release/product-launch-decision.example.json` 保留 M87 原始 Lane A／undecided 歷史範例，不是
目前客群設定。即使 status 是 `PROPOSED`，validator 也會拒絕 lane 與已選 sales／App／
entitlement path 的矛盾組合。

因此一般驗證會回 `PRODUCT_LAUNCH_DECISION_PROPOSED_VALID`，但 production gate 必須使用
`--require-approved`，目前一定 fail closed：

```sh
python3 tools/validate_product_launch_decision.py \
  --decision release/product-launch-decision.international-developer-proposed.json

python3 tools/validate_product_launch_decision.py \
  --decision /controlled/product-launch-decision.json \
  --require-approved
```

`APPROVED` profile 必須指定 1–8 個排序且不重複的大寫雙字母 market codes、非 placeholder
的 provider／owner／legal／SDK IDs、至少一個 Companion platform、互相一致的 lane／sales／
distribution／entitlement path，並把有效期限制在 180 天內。Validator 只驗證 code shape；
真正 ISO 3166-1 membership 與法規適用性由 legal authority 負責。核准 profile 的 exact
SHA-256 與 WORM URI 必須納入 `legal_market` production evidence；不新增第十六個
market-release evidence domain。

## 已決定與批准前缺口

已決定：個人開發者、Lane B、六個 Wave 1 候選市場、官網 checkout、公開免費／
consumption-only App、web billing adapter。仍須選定 merchant legal entity、billing
provider、IdP、HSM／KMS、正式 SDK module owner、legal approver 與 decision owner；並逐市場
完成 consumer／tax／privacy、RF／label、App review、退款與 live billing qualification。

這些缺口不阻止 provider-neutral 工程繼續，但 production adapter、App distribution 與市場
發布不能誠實地宣稱完成。
