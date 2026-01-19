package policy

import (
	"strings"
	"testing"
)

func TestOriginPolicy_Validate_EmptyAllowlist(t *testing.T) {
	// Empty allowlist should allow all origins
	policy := NewOriginPolicy([]string{})

	testCases := []string{
		"official",
		"verified",
		"community",
		"unknown",
		"",
	}

	for _, origin := range testCases {
		t.Run("origin="+origin, func(t *testing.T) {
			err := policy.Validate(origin)
			if err != nil {
				t.Errorf("expected empty allowlist to allow origin %q, got error: %v", origin, err)
			}
		})
	}
}

func TestOriginPolicy_Validate_AllowedOrigins(t *testing.T) {
	// Policy allowing only official and verified origins
	policy := NewOriginPolicy([]string{"official", "verified"})

	allowedCases := []struct {
		name   string
		origin string
	}{
		{"exact match official", "official"},
		{"exact match verified", "verified"},
		{"case insensitive OFFICIAL", "OFFICIAL"},
		{"case insensitive Verified", "Verified"},
		{"with whitespace", " official "},
	}

	for _, tc := range allowedCases {
		t.Run(tc.name, func(t *testing.T) {
			err := policy.Validate(tc.origin)
			if err != nil {
				t.Errorf("expected origin %q to be allowed, got error: %v", tc.origin, err)
			}
		})
	}
}

func TestOriginPolicy_Validate_BlockedOrigins(t *testing.T) {
	// Policy allowing only official and verified origins
	policy := NewOriginPolicy([]string{"official", "verified"})

	blockedCases := []struct {
		name   string
		origin string
	}{
		{"community origin", "community"},
		{"unknown origin", "unknown"},
		{"empty origin", ""},
		{"partial match", "offic"},
	}

	for _, tc := range blockedCases {
		t.Run(tc.name, func(t *testing.T) {
			err := policy.Validate(tc.origin)
			if err == nil {
				t.Errorf("expected origin %q to be blocked, but it was allowed", tc.origin)
			}

			// Verify error message contains the origin
			errMsg := err.Error()
			if !strings.Contains(errMsg, "not allowed by policy") {
				t.Errorf("expected error message to mention policy, got: %v", errMsg)
			}
		})
	}
}

func TestOriginPolicy_Validate_CaseInsensitive(t *testing.T) {
	// Test case insensitivity
	policy := NewOriginPolicy([]string{"Official", "VERIFIED"})

	testCases := []struct {
		origin      string
		shouldAllow bool
	}{
		{"official", true},
		{"OFFICIAL", true},
		{"Official", true},
		{"oFfIcIaL", true},
		{"verified", true},
		{"VERIFIED", true},
		{"Verified", true},
		{"vErIfIeD", true},
		{"community", false},
		{"COMMUNITY", false},
	}

	for _, tc := range testCases {
		t.Run(tc.origin, func(t *testing.T) {
			err := policy.Validate(tc.origin)
			if tc.shouldAllow && err != nil {
				t.Errorf("expected origin %q to be allowed (case-insensitive), got error: %v", tc.origin, err)
			}
			if !tc.shouldAllow && err == nil {
				t.Errorf("expected origin %q to be blocked, but it was allowed", tc.origin)
			}
		})
	}
}

func TestOriginPolicy_Validate_Whitespace(t *testing.T) {
	// Test whitespace handling
	policy := NewOriginPolicy([]string{" official ", "verified"})

	testCases := []struct {
		origin      string
		shouldAllow bool
	}{
		{"official", true},
		{" official", true},
		{"official ", true},
		{" official ", true},
		{"\tofficial\t", true},
		{"verified", true},
		{" verified ", true},
		{"community", false},
		{" community ", false},
	}

	for _, tc := range testCases {
		t.Run("'"+tc.origin+"'", func(t *testing.T) {
			err := policy.Validate(tc.origin)
			if tc.shouldAllow && err != nil {
				t.Errorf("expected origin %q to be allowed (whitespace trimmed), got error: %v", tc.origin, err)
			}
			if !tc.shouldAllow && err == nil {
				t.Errorf("expected origin %q to be blocked, but it was allowed", tc.origin)
			}
		})
	}
}

func TestOriginPolicy_IsEmpty(t *testing.T) {
	testCases := []struct {
		name           string
		allowedOrigins []string
		expectedEmpty  bool
	}{
		{"nil list", nil, true},
		{"empty list", []string{}, true},
		{"single origin", []string{"official"}, false},
		{"multiple origins", []string{"official", "verified"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy := NewOriginPolicy(tc.allowedOrigins)
			isEmpty := policy.IsEmpty()
			if isEmpty != tc.expectedEmpty {
				t.Errorf("expected IsEmpty()=%v for %v, got %v", tc.expectedEmpty, tc.allowedOrigins, isEmpty)
			}
		})
	}
}

func TestOriginPolicy_ErrorMessage(t *testing.T) {
	policy := NewOriginPolicy([]string{"official", "verified"})

	err := policy.Validate("community")
	if err == nil {
		t.Fatal("expected error for blocked origin")
	}

	errMsg := err.Error()

	// Error should mention the origin that was blocked
	if !strings.Contains(errMsg, "community") {
		t.Errorf("expected error to mention 'community', got: %s", errMsg)
	}

	// Error should mention it's a policy violation
	if !strings.Contains(errMsg, "not allowed by policy") {
		t.Errorf("expected error to mention policy, got: %s", errMsg)
	}

	// Error should list allowed origins
	if !strings.Contains(errMsg, "official") || !strings.Contains(errMsg, "verified") {
		t.Errorf("expected error to list allowed origins, got: %s", errMsg)
	}
}

func TestOriginPolicy_RealWorldScenarios(t *testing.T) {
	scenarios := []struct {
		name           string
		allowedOrigins []string
		testOrigins    map[string]bool // origin -> shouldAllow
	}{
		{
			name:           "strict official only",
			allowedOrigins: []string{"official"},
			testOrigins: map[string]bool{
				"official":  true,
				"verified":  false,
				"community": false,
			},
		},
		{
			name:           "official and verified",
			allowedOrigins: []string{"official", "verified"},
			testOrigins: map[string]bool{
				"official":  true,
				"verified":  true,
				"community": false,
			},
		},
		{
			name:           "allow all (enterprise default)",
			allowedOrigins: []string{},
			testOrigins: map[string]bool{
				"official":  true,
				"verified":  true,
				"community": true,
			},
		},
		{
			name:           "community only (development)",
			allowedOrigins: []string{"community"},
			testOrigins: map[string]bool{
				"official":  false,
				"verified":  false,
				"community": true,
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			policy := NewOriginPolicy(scenario.allowedOrigins)

			for origin, shouldAllow := range scenario.testOrigins {
				err := policy.Validate(origin)
				if shouldAllow && err != nil {
					t.Errorf("scenario %q: expected origin %q to be allowed, got error: %v",
						scenario.name, origin, err)
				}
				if !shouldAllow && err == nil {
					t.Errorf("scenario %q: expected origin %q to be blocked, but it was allowed",
						scenario.name, origin)
				}
			}
		})
	}
}
