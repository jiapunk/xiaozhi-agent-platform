package entitlementadapter

import (
	"errors"
	"testing"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
)

func TestPublicErrorTaxonomyHidesInternalDetails(t *testing.T) {
	for name, testCase := range map[string]struct {
		internal error
		public   error
	}{
		"invalid":      {accountauth.ErrInvalid, ErrInvalid},
		"unauthorized": {accountauth.ErrEntitlementUpdateUnauthorized, ErrUnauthorized},
		"not found":    {accountauth.ErrNotFound, ErrNotFound},
		"conflict":     {accountauth.ErrConflict, ErrConflict},
		"unavailable":  {accountauth.ErrUnavailable, ErrUnavailable},
		"unknown":      {errors.New("private provider detail"), ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			if result := publicError(testCase.internal); result != testCase.public {
				t.Fatalf("public error=%v want=%v", result, testCase.public)
			}
		})
	}
}
