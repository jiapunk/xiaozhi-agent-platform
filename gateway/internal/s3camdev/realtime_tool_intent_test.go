package s3camdev

import "testing"

func TestProposedToolConflictClearArithmetic(t *testing.T) {
	for _, transcript := range []string{
		"一加一", "一加一等於多少？", "請問一加一等於幾", "请帮我算一加一等于多少",
		"幫我算 12 減去 3", "計算二乘以三", "十除以二是多少", "一加二乘三", "負三加二",
		"1+1", "1 - 1", "12 * 3", "12 ÷ 4", "(1+2)*3", "１＋２", "1.5加2.5", "三點五減一點五",
		"再加三", "那再加上3呢", "接著減二", "然后乘以四", "再除以2", "我說再加三",
		"不是匯率，是一加一", "不是汇率，我是说一加一", "我問的是一加一，不是匯率", "一加一，不要查匯率",
		"What is one plus one?", "What is 3 minus 2?", "Calculate (2+3)*4.", "one multiplied by two",
		"please compute twenty one plus three", "then add three", "and then minus 2", "add two and three",
		"subtract three from five", "multiply two by three", "divide six by two", "not exchange rate, one plus one",
	} {
		for _, tool := range []string{"web_search", "web_fetch", "market_quote"} {
			t.Run(transcript+"/"+tool, func(t *testing.T) {
				if got := ProposedToolConflict(transcript, tool, `{"query":"USD TWD exchange rate"}`); got != ToolConflictArithmeticLookup {
					t.Fatalf("clear arithmetic conflict=%q", got)
				}
			})
		}
	}
}

func TestProposedToolConflictDoesNotOverruleOtherDomains(t *testing.T) {
	for _, transcript := range []string{
		"", "對", "那個是多少", "再來", "加", "一", "1", "等等", "不是匯率",
		"台積電漲3%", "台积电涨3%", "Tesla plus 3 percent", "AAPL +3%", "2330 股價加三",
		"美元加三", "美元再加三", "3美元加2美元", "$3+$2", "USD plus 3", "加幣兌美元的匯率",
		"再加三分鐘", "倒數再加三分鐘", "闹钟加三分钟", "timer plus three minutes", "音量再加三",
		"9月5日", "2026-09-05", "2026/9/5", "2026年9月5日加三天", "明天三點", "10:30",
		"一加一股價", "搜尋一加一的典故", "請上網查一加一等於多少", "what is the stock price of one plus one",
		"不是一加一，是匯率", "不要算一加一", "什麼是匯率", "匯率是什麼意思", "汇率的历史",
		"explain exchange rates", "what is an exchange rate", "historical exchange rate policy",
		"剛才那個匯率呢", "same pair exchange rate today", "that rate", "previous currency rate",
		"美元對台幣匯率", "美元兑人民币汇率", "USD/TWD exchange rate", "what is the GBP EUR exchange rate",
		"新台幣對港元匯率", "阿根廷披索換埃及鎊的匯率", "索莫尼對列克的匯率", "BTC/USD 匯率",
	} {
		t.Run(transcript, func(t *testing.T) {
			if got := ProposedToolConflict(transcript, "web_search", `{"query":"today USD TWD"}`); got != "" {
				t.Fatalf("unclear or other-domain query was overruled: %q", got)
			}
		})
	}
}

func TestProposedToolConflictMissingCurrencyPair(t *testing.T) {
	for _, transcript := range []string{
		"匯率是多少", "今天匯率是多少", "請幫我查今天的匯率", "查一下最新匯率", "目前汇率是多少",
		"美元匯率是多少", "查詢人民幣今天匯率", "港幣的匯率", "日圓今天匯率多少",
		"what is the exchange rate?", "what's the exchange rate today?", "check current USD exchange rate",
		"please tell me the current exchange rate", "current currency rate", "check forex rate today",
	} {
		t.Run(transcript, func(t *testing.T) {
			if got := ProposedToolConflict(transcript, "web_search", `{"query":"USD TWD exchange rate"}`); got != ToolConflictCurrencyPair {
				t.Fatalf("model-invented pair was not rejected: %q", got)
			}
		})
	}
}

func TestProposedToolConflictNeverInfersIntentFromArgumentsOrBlocksDeviceTools(t *testing.T) {
	for _, tool := range []string{"device_set_volume", "watch_set_timer", "watch_get_status", "camera_analyze", ""} {
		if got := ProposedToolConflict("再加三", tool, "{}"); got != "" {
			t.Fatalf("non-lookup tool %q was blocked: %q", tool, got)
		}
	}
	for _, transcript := range []string{"", "沒聽清楚", "那個", "對"} {
		if got := ProposedToolConflict(transcript, "web_search", `{"query":"one plus one"}`); got != "" {
			t.Fatalf("intent invented from tool arguments: %q", got)
		}
	}
}
