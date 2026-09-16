package generation

import (
	"context"
	"testing"
	"time"
)

func TestReplicaDrainFenceNeverAllowsOldAndNewTogether(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	ctx := context.Background()
	oldControl, err := NewReplicaGuard(fixture.control, testGenesis)
	if err != nil {
		t.Fatal(err)
	}
	oldOrigin, err := NewReplicaGuard(fixture.origin, testGenesis)
	if err != nil {
		t.Fatal(err)
	}
	newControl, err := NewReplicaGuard(fixture.control, testNext)
	if err != nil {
		t.Fatal(err)
	}
	newOrigin, err := NewReplicaGuard(fixture.origin, testNext)
	if err != nil {
		t.Fatal(err)
	}
	guards := []*ReplicaGuard{oldControl, oldOrigin, newControl, newOrigin}
	for _, guard := range guards {
		guard.now = func() time.Time { return *fixture.now }
	}
	if err := oldControl.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := oldOrigin.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	assertGatePair(t, true, false, oldControl, newControl)
	state, err := fixture.publisher.GetState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, err = fixture.publisher.Publish(ctx, PublishRequest{
		ExpectedRevision: state.Revision, ExpectedActive: state.Active, Pending: testNext,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := oldControl.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := oldOrigin.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	assertGatePair(t, true, false, oldControl, newControl)
	if err := newControl.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := newOrigin.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	view, _ := newOrigin.Status()
	if view.Phase != PhaseDraining {
		t.Fatalf("phase=%s", view.Phase)
	}
	// Old replicas may still hold their last pre-drain lease; the new generation
	// remains fenced for the entire interval.
	assertNeverBoth(t, oldControl, newControl)
	*fixture.now = (*fixture.now).Add(StateLeaseDuration + time.Second)
	assertGatePair(t, false, false, oldControl, newControl)
	if _, err := fixture.store.Advance(time.Unix(view.DrainUntil-1, 0)); err != nil {
		t.Fatal(err)
	}
	assertGatePair(t, false, false, oldControl, newControl)
	*fixture.now = time.Unix(view.DrainUntil, 0)
	if _, err := fixture.store.Advance(*fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := newControl.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := newOrigin.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	assertGatePair(t, false, true, oldControl, newControl)
	assertGatePair(t, false, true, oldOrigin, newOrigin)
	final, _ := fixture.store.Snapshot()
	if final.Phase != PhaseStable || final.Active != testNext {
		t.Fatalf("not converged: %#v", final)
	}
}

func TestGuardFailsClosedOnCoordinatorOutageAndDelayedResponse(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	guard, err := NewReplicaGuard(fixture.control, testGenesis)
	if err != nil {
		t.Fatal(err)
	}
	guard.now = func() time.Time { return *fixture.now }
	if err := guard.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !guard.AllowOTA() {
		t.Fatal("fresh authenticated state did not allow local active")
	}
	fixture.server.Close()
	*fixture.now = (*fixture.now).Add(StateLeaseDuration + time.Nanosecond)
	if guard.AllowOTA() || guard.Ready() {
		t.Fatal("expired coordinator lease remained serving")
	}
	// A response accepted late is still leased from request start.
	view, _ := guard.Status()
	requestStarted := *fixture.now
	guard.accept(view, requestStarted)
	*fixture.now = (*fixture.now).Add(StateLeaseDuration + time.Nanosecond)
	if guard.AllowOTA() {
		t.Fatal("delayed response extended its state lease")
	}
}

func assertGatePair(t *testing.T, oldExpected, newExpected bool,
	oldGuard, newGuard *ReplicaGuard) {
	t.Helper()
	if oldGuard.AllowOTA() != oldExpected || newGuard.AllowOTA() != newExpected {
		t.Fatalf("gate pair old=%v new=%v expected old=%v new=%v",
			oldGuard.AllowOTA(), newGuard.AllowOTA(), oldExpected, newExpected)
	}
	assertNeverBoth(t, oldGuard, newGuard)
}

func assertNeverBoth(t *testing.T, oldGuard, newGuard *ReplicaGuard) {
	t.Helper()
	if oldGuard.AllowOTA() && newGuard.AllowOTA() {
		t.Fatal("old and new generations were simultaneously allowed")
	}
}
