package discovery

import "testing"

func TestCheckHostInvalidIP(t *testing.T) {
	_, err := CheckHost("999.999.999.999")

	if err == nil {
		t.Fatal("esperava um erro para um endereço IP inválido")
	}
}

func TestCheckHostRejectsIPv6(t *testing.T) {
	_, err := CheckHost("::1")

	if err == nil {
		t.Fatal("esperava um erro para um endereço IPv6")
	}
}
