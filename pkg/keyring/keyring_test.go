package keyring

import (
	"os"
	"testing"
)

func TestSetSecretAndGetSecret(t *testing.T) {
	os.Setenv("APPGATECTL_BEARER", "header-token-value")
	if err := setSecret("foo", "bar"); err != nil {
		t.Errorf("setSecret() Got error = %v, wantErr none", err)
	}
	secret, err := getSecret("foo")
	if err != nil {
		t.Errorf("GetSecret() got error %v, want none", err)
	}
	if secret != "bar" {
		t.Fatalf("got secret, wrong value, expected bar, got %s", secret)
	}
}
