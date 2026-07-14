package registry

import "testing"

func TestOutdated(t *testing.T) {
	tests := []struct {
		name     string
		reported string
		minimum  string
		want     bool
	}{
		{"below minimum", "1.1.9", "1.2.0", true},
		{"equal to minimum", "1.2.0", "1.2.0", false},
		{"above minimum", "1.3.0", "1.2.0", false},
		{"bare reported, bare minimum", "1.1.9", "1.2.0", true},
		{"v-prefixed reported, bare minimum", "v1.1.9", "1.2.0", true},
		{"bare reported, v-prefixed minimum", "1.3.0", "v1.2.0", false},
		{"v-prefixed reported, v-prefixed minimum", "v1.3.0", "v1.2.0", false},
		{"empty minimum: gate off", "0.0.1", "", false},
		{"empty minimum, empty reported: gate off", "", "", false},
		{"empty reported, minimum set: fails closed", "", "1.2.0", true},
		{"malformed reported \"abc\": fails closed", "abc", "1.2.0", true},
		{"malformed reported \"1.2.x\": fails closed", "1.2.x", "1.2.0", true},
		{"malformed reported \"latest\": fails closed", "latest", "1.2.0", true},
		{"malformed minimum: defensive false", "0.0.1", "not-a-version", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Outdated(tt.reported, tt.minimum)
			if got != tt.want {
				t.Errorf("Outdated(%q, %q) = %v, want %v", tt.reported, tt.minimum, got, tt.want)
			}
		})
	}
}

func TestValidVersion(t *testing.T) {
	tests := []struct {
		name string
		v    string
		want bool
	}{
		{"bare valid", "1.2.0", true},
		{"v-prefixed valid", "v1.2.0", true},
		{"empty", "", false},
		{"malformed", "abc", false},
		{"malformed with trailing garbage", "1.2.x", false},
		{"the word latest", "latest", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidVersion(tt.v)
			if got != tt.want {
				t.Errorf("ValidVersion(%q) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}
