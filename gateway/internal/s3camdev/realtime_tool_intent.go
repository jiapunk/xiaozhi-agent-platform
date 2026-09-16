package s3camdev

import (
	"regexp"
	"strings"
	"unicode"
)

const (
	ToolConflictArithmeticLookup = "arithmetic_does_not_require_lookup"
	ToolConflictCurrencyPair     = "exchange_rate_currency_pair_required"
)

// ProposedToolConflict is a conservative contradiction check, not a general
// intent classifier and not a calculator. Call it only with the transcript
// bound to THIS input turn. Empty/unclear text permits normal model handling.
// Model-generated arguments cannot supply facts omitted by the user: in
// particular a query inventing USD/TWD does not establish that currency pair.
func ProposedToolConflict(transcript, tool, arguments string) string {
	switch tool {
	case "web_search", "web_fetch", "market_quote":
	default:
		return ""
	}
	_ = arguments
	if strings.TrimSpace(transcript) == "" {
		return ""
	}
	if isUnambiguousArithmetic(transcript) {
		return ToolConflictArithmeticLookup
	}
	if isUnspecifiedCurrencyPair(transcript) {
		return ToolConflictCurrencyPair
	}
	return ""
}

var arithmeticNumber = regexp.MustCompile(`^(?:[+-]?(?:[0-9]+(?:\.[0-9]+)?|[零〇一二兩两三四五六七八九十百千萬万億亿]+(?:[點点][零〇一二兩两三四五六七八九]+)?)|(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty)(?:(?:hundred|thousand|million|and|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty))*)`)

func normalizeArithmeticText(text string) string {
	text = strings.NewReplacer("＋", "+", "－", "-", "−", "-", "×", "*", "÷", "/",
		"負", "-", "负", "-",
		"（", "(", "）", ")", "＝", "=", "０", "0", "１", "1", "２", "2",
		"３", "3", "４", "4", "５", "5", "６", "6", "７", "7", "８", "8", "９", "9").Replace(text)
	text = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || strings.ContainsRune("，,。！？!?、：:；;\"'「」『』", r) {
			return -1
		}
		return unicode.ToLower(r)
	}, text)
	return strings.TrimRight(text, ".")
}

func trimArithmeticWording(text string) string {
	prefixes := []string{
		"不是匯率我是說", "不是汇率我是说", "不是匯率是", "不是汇率是",
		"我說的是", "我说的是", "我問的是", "我问的是", "我是說", "我是说",
		"我說", "我说", "我問", "我问", "notexchangerateits", "notexchangerate", "isaid", "imeant",
		"請幫我計算", "请帮我计算", "請幫我算一下", "请帮我算一下",
		"幫我計算", "帮我计算", "幫我算一下", "帮我算一下", "幫我算", "帮我算",
		"pleasecalculate", "pleasecompute", "howmuchis", "whatis", "whats", "whatdoes",
		"calculate", "compute", "please", "請問", "请问", "計算", "计算", "算一下", "算算", "請", "请", "那", "所以",
	}
	suffixes := []string{
		"不是匯率問題", "不是汇率问题", "不是匯率", "不是汇率", "不要查匯率", "不要查汇率",
		"的結果是什麼", "的结果是什么", "的結果", "的结果", "答案是多少", "結果是多少", "结果是多少",
		"等於多少", "等于多少", "等於什麼", "等于什么", "等於甚麼", "等於幾", "等于几",
		"是多少", "是幾", "是几", "怎麼算", "怎么算", "equals", "equal", "等於", "等于", "多少", "呢", "啊", "呀", "喔", "哦",
	}
	for range 8 {
		previous := text
		for _, prefix := range prefixes {
			if strings.HasPrefix(text, prefix) {
				text = strings.TrimPrefix(text, prefix)
				break
			}
		}
		for _, suffix := range suffixes {
			if strings.HasSuffix(text, suffix) {
				text = strings.TrimSuffix(text, suffix)
				break
			}
		}
		if previous == text {
			break
		}
	}
	return text
}

var arithmeticOperators = []string{
	"multipliedby", "dividedby", "multiplyby", "divideby", "subtract", "plus", "minus", "times", "add",
	"加上", "減去", "减去", "乘以", "乘上", "除以", "等於", "等于", "加", "減", "减", "乘", "除", "+", "-", "*", "/", "=",
}

func takeArithmeticOperator(text string) (string, bool) {
	for _, operator := range arithmeticOperators {
		if strings.HasPrefix(text, operator) {
			return strings.TrimPrefix(text, operator), true
		}
	}
	return text, false
}

func isUnambiguousArithmetic(text string) bool {
	text = trimArithmeticWording(normalizeArithmeticText(text))
	if arithmeticDateOnly.MatchString(text) {
		return false
	}
	// Follow-up ellipsis is admitted only with an explicit continuation cue.
	// "再加三分鐘", "美元加三" and stock changes retain their units/nouns and
	// cannot pass the complete arithmetic grammar below.
	for _, prefix := range []string{"andthen", "then", "再來", "再来", "接著", "接着", "然後", "然后", "再"} {
		if strings.HasPrefix(text, prefix) {
			rest, operation := takeArithmeticOperator(strings.TrimPrefix(text, prefix))
			if operation && arithmeticNumber.FindString(rest) == rest && rest != "" {
				return true
			}
		}
	}
	// English imperative form, e.g. "add two and three". This parser only
	// verifies a complete numeric expression and never evaluates its value.
	for _, prefix := range []string{"add", "subtract", "multiply", "divide"} {
		if !strings.HasPrefix(text, prefix) {
			continue
		}
		rest := strings.TrimPrefix(text, prefix)
		for _, separator := range []string{"and", "from", "to", "by"} {
			parts := strings.Split(rest, separator)
			if len(parts) == 2 && parts[0] != "" && parts[1] != "" &&
				arithmeticNumber.FindString(parts[0]) == parts[0] && arithmeticNumber.FindString(parts[1]) == parts[1] {
				return true
			}
		}
	}
	depth, operators := 0, 0
	expectNumber := true
	for text != "" {
		if expectNumber {
			if strings.HasPrefix(text, "(") {
				depth++
				text = text[1:]
				continue
			}
			number := arithmeticNumber.FindString(text)
			if number == "" {
				return false
			}
			text = strings.TrimPrefix(text, number)
			expectNumber = false
			continue
		}
		if strings.HasPrefix(text, ")") {
			if depth == 0 {
				return false
			}
			depth--
			text = text[1:]
			continue
		}
		rest, operation := takeArithmeticOperator(text)
		if !operation {
			return false
		}
		operators++
		expectNumber = true
		text = rest
	}
	return !expectNumber && depth == 0 && operators > 0
}

var arithmeticDateOnly = regexp.MustCompile(`^[0-9]{4}[-/][0-9]{1,2}[-/][0-9]{1,2}$`)

var currencyAliasReplacer = strings.NewReplacer(
	"新台幣", " TWD ", "新台币", " TWD ", "人民幣", " CNY ", "人民币", " CNY ",
	"加拿大元", " CAD ", "新加坡元", " SGD ", "澳門幣", " MOP ", "澳门币", " MOP ",
	"澳門元", " MOP ", "澳门元", " MOP ", "瑞士法郎", " CHF ",
	"美元", " USD ", "美金", " USD ", "美幣", " USD ", "美币", " USD ",
	"台幣", " TWD ", "台币", " TWD ", "港幣", " HKD ", "港币", " HKD ", "港元", " HKD ",
	"日圓", " JPY ", "日圆", " JPY ", "日元", " JPY ", "日幣", " JPY ", "日币", " JPY ",
	"歐元", " EUR ", "欧元", " EUR ", "英鎊", " GBP ", "英镑", " GBP ",
	"加幣", " CAD ", "加币", " CAD ", "澳幣", " AUD ", "澳币", " AUD ", "澳元", " AUD ",
	"韓元", " KRW ", "韩元", " KRW ", "韓圜", " KRW ", "韓幣", " KRW ", "韩币", " KRW ",
	"瑞郎", " CHF ", "新幣", " SGD ", "新币", " SGD ", "泰銖", " THB ", "泰铢", " THB ",
)

var currencyCode = regexp.MustCompile(`(?i)\b(?:USD|TWD|CNY|RMB|HKD|JPY|EUR|GBP|CAD|AUD|KRW|CHF|SGD|THB|NZD|MOP|AED|ARS|BDT|BGN|BHD|BND|BOB|BRL|CLP|COP|CRC|CZK|DKK|DOP|DZD|EGP|ETB|FJD|GEL|GHS|HUF|IDR|ILS|INR|ISK|JMD|JOD|KES|KHR|KWD|KZT|LAK|LBP|LKR|MAD|MDL|MNT|MUR|MXN|MYR|NAD|NGN|NOK|NPR|OMR|PAB|PEN|PHP|PKR|PLN|PYG|QAR|RON|RSD|RUB|SAR|SEK|TND|TRY|TZS|UAH|UGX|UYU|UZS|VND|ZAR|ZMW)\b`)

func isUnspecifiedCurrencyPair(transcript string) bool {
	text := strings.ToLower(strings.TrimSpace(transcript))
	if !containsAnyFolded(text, []string{"匯率", "汇率", "exchange rate", "currency rate", "fx rate", "forex rate"}) {
		return false
	}
	// Definitions, negation and explicit references need semantic/contextual
	// interpretation. Do not invent a contradiction from keyword occurrence.
	if containsAnyFolded(text, []string{
		"不是", "不要", "不用", "不查", "別查", "别查", "不問", "不问", "定義", "定义", "意思", "什麼是", "什么是",
		"解釋", "解释", "原理", "歷史", "历史", "剛才", "刚才", "之前", "那個", "那个", "這個", "这个", "上述", "同一",
		"not ", "don't", "do not", "definition", "meaning", "explain", "what is an", "history", "same pair", "that rate", "those currencies",
	}) {
		return false
	}
	withCodes := currencyAliasReplacer.Replace(text)
	mentions := currencyCode.FindAllString(withCodes, -1)
	if len(mentions) >= 2 {
		return false
	}
	remaining := currencyCode.ReplaceAllString(withCodes, "")
	remaining = normalizeArithmeticText(remaining)
	// Reject only a wholly recognized, underspecified current-quote request.
	// Unknown currency names, crypto, additional instructions or other domain
	// nouns remain in the text and deliberately make the guard abstain.
	for _, term := range []string{
		"forexrate", "exchangerate", "currencyrate", "fxrate", "匯率", "汇率",
		"請幫我查詢", "请帮我查询", "幫我查詢", "帮我查询", "請幫我查", "请帮我查", "幫我查", "帮我查",
		"查詢一下", "查询一下", "查詢", "查询", "查一下", "搜尋", "搜索", "請問", "请问",
		"現在", "现在", "目前", "當前", "当前", "今天", "今日", "最新", "即時", "即时",
		"是多少", "多少", "報價", "报价", "告訴我", "告诉我", "看一下", "看", "查", "請", "请", "呢", "的", "是", "啊",
		"couldyou", "canyou", "please", "tellme", "showme", "lookup", "check", "current", "latest", "today", "now", "whatis", "whats", "the", "for", "of", "howmuch",
	} {
		remaining = strings.ReplaceAll(remaining, term, "")
	}
	return remaining == ""
}
