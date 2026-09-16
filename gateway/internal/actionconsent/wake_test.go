package actionconsent

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWakePayloadIsConstantContentFreeAndCopied(t *testing.T) {
	want := []byte(`{"version":1,"kind":"action-consent-wake"}`)
	first := CanonicalWakePayload()
	if !bytes.Equal(first, want) {
		t.Fatalf("wake payload=%s", first)
	}
	for _, forbidden := range []string{
		"challenge", "device", "owner", "indicator", "approve", "deny",
		"argument", "prompt", "decision", "expires", "http", "token",
	} {
		if strings.Contains(string(first), forbidden) {
			t.Fatalf("wake payload contains %q", forbidden)
		}
	}
	first[0] = 'X'
	if !bytes.Equal(CanonicalWakePayload(), want) {
		t.Fatal("caller mutated the canonical wake payload")
	}
}

func TestReferenceWakeOutboxLeasesRetriesAndAcknowledges(t *testing.T) {
	now := time.Now().UTC()
	store, _ := NewStore(8)
	challenge := testChallenge(now)
	if err := store.Register(challenge, now); err != nil {
		t.Fatal(err)
	}
	wake, found, err := store.ClaimWake("notifier-1", now, time.Second)
	if err != nil || !found || wake.WakeID != challenge.ChallengeID ||
		wake.Target != testActor() || wake.Attempts != 1 ||
		!wake.ExpiresAt.Equal(challenge.ExpiresAt) {
		t.Fatalf("first wake=%#v found=%t err=%v", wake, found, err)
	}
	if _, found, err := store.ClaimWake(
		"notifier-2", now, time.Second); err != nil || found {
		t.Fatalf("concurrent lease found=%t err=%v", found, err)
	}
	if err := store.AcknowledgeWake(
		"notifier-2", wake.WakeID, now); err != ErrConflict {
		t.Fatalf("wrong-worker acknowledge=%v", err)
	}
	if err := store.RetryWake(
		"notifier-1", wake.WakeID, now, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.ClaimWake(
		"notifier-2", now.Add(500*time.Millisecond), time.Second); found {
		t.Fatal("wake escaped before retry time")
	}
	wake, found, err = store.ClaimWake(
		"notifier-2", now.Add(time.Second), time.Second)
	if err != nil || !found || wake.Attempts != 2 {
		t.Fatalf("retried wake=%#v found=%t err=%v", wake, found, err)
	}
	if err := store.AcknowledgeWake(
		"notifier-2", wake.WakeID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.ClaimWake(
		"notifier-3", now.Add(2*time.Second), time.Second); err != nil || found {
		t.Fatalf("acknowledged wake found=%t err=%v", found, err)
	}
}

func TestReferenceWakeOutboxDropsDecidedAndExpiredWork(t *testing.T) {
	now := time.Now().UTC()
	store, _ := NewStore(8)
	challenge := testChallenge(now)
	if err := store.Register(challenge, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(testActor(), testRequest(), now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.ClaimWake(
		"notifier-1", now, time.Second); err != nil || found {
		t.Fatalf("decided wake found=%t err=%v", found, err)
	}

	expiring := testChallenge(now)
	expiring.ChallengeID = "YWJjZGVmZ2hpamtsbW5vcA"
	expiring.SessionID = "session-2"
	expiring.RequestID = 43
	expiring.ExpiresAt = now.Add(time.Second)
	if err := store.Register(expiring, now); err != nil {
		t.Fatal(err)
	}
	wake, found, err := store.ClaimWake(
		"notifier-1", now, time.Second)
	if err != nil || !found {
		t.Fatalf("expiring claim=%#v found=%t err=%v", wake, found, err)
	}
	if err := store.RetryWake("notifier-1", wake.WakeID, now,
		time.Second); err != ErrExpired {
		t.Fatalf("expiry-crossing retry=%v", err)
	}
}

func TestReferenceWakeOutboxHasOneConcurrentLeaseWinner(t *testing.T) {
	now := time.Now().UTC()
	store, _ := NewStore(8)
	if err := store.Register(testChallenge(now), now); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, found, err := store.ClaimWake(
				"notifier-"+string(rune('a'+index)), now, time.Second)
			if err != nil {
				t.Errorf("claim: %v", err)
			} else if found {
				winners.Add(1)
			}
		}(index)
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatalf("lease winners=%d", winners.Load())
	}
}
