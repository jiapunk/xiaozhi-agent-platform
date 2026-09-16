package s3camdev

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestConversationWindowStaysBoundedAcrossManyTurns(t *testing.T) {
	var window conversationWindow
	longReply := strings.Repeat("回", maxConversationContentRunes+300) + "最後結論"
	for turn := 0; turn < 20; turn++ {
		window.Add(fmt.Sprintf("使用者第 %d 輪", turn),
			fmt.Sprintf("第 %d 輪：%s", turn, longReply))
	}

	snapshot := window.Snapshot()
	if len(snapshot) != maxConversationTurns*2 {
		t.Fatalf("conversation entries=%d, want %d",
			len(snapshot), maxConversationTurns*2)
	}
	if !strings.Contains(snapshot[0].Content, "第 17 輪") ||
		!strings.Contains(snapshot[len(snapshot)-1].Content, "最後結論") {
		t.Fatalf("window did not retain the newest context: %+v", snapshot)
	}
	for _, entry := range snapshot {
		if runes := utf8.RuneCountInString(entry.Content); runes > maxConversationContentRunes {
			t.Fatalf("history entry has %d runes", runes)
		}
	}
	entries, runes := window.Metrics()
	if entries != len(snapshot) || runes > maxConversationWindowTotalRunes {
		t.Fatalf("history metrics entries=%d runes=%d", entries, runes)
	}
}

func TestStartingAndCancellingTurnsStopsPreviousWork(t *testing.T) {
	session := &deviceSession{}
	first, finishFirst := session.beginTurn(context.Background())
	defer finishFirst()
	second, finishSecond := session.beginTurn(context.Background())
	defer finishSecond()
	select {
	case <-first.Done():
	default:
		t.Fatal("starting a new turn did not cancel the previous turn")
	}
	if second.Err() != nil {
		t.Fatalf("new turn was cancelled unexpectedly: %v", second.Err())
	}
	session.cancelTurn()
	select {
	case <-second.Done():
	default:
		t.Fatal("explicit abort did not cancel the active turn")
	}
}

func TestConversationCompactionKeepsBeginningAndConclusion(t *testing.T) {
	content := "開頭前提" + strings.Repeat("中", maxConversationContentRunes) + "最後建議"
	compact := compactConversationContent(content)
	if utf8.RuneCountInString(compact) != maxConversationContentRunes ||
		!strings.HasPrefix(compact, "開頭前提") ||
		!strings.HasSuffix(compact, "最後建議") ||
		!strings.Contains(compact, "…") {
		t.Fatalf("unexpected compact history: %q", compact)
	}
}
