package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"math/big"
	"reflect"
	"regexp"
	"sort"
	"testing"
	"time"
)

func TestChangelogUpToDate(t *testing.T) {
	filename := "CHANGELOG.md"
	match := []byte("## [" + version + "]")
	sr := `## \[(\d+\.)*(\d+)\]`

	changelog, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Error("Can not read", filename)
	}

	curIndex := bytes.Index(changelog, match)
	if curIndex < 0 {
		t.Error("Entry for version", version, "not found in", filename)
	}

	r, err := regexp.Compile(sr)
	if err != nil {
		t.Error("Can not compile regexp", sr)
	}

	firstIndex := r.FindIndex(changelog)
	switch {
	case firstIndex == nil:
		t.Error("Could not find any string matching", sr, "in", filename)
	case curIndex > firstIndex[0]:
		t.Error(version, "is not the latest entry in", filename)
	}
}

// mockCert creates an SSL certificate with expiration timestamp 30 days in the future
func mockCert(host string, altDNSNames []string, validForDays int) (*x509.Certificate, error) {
	daysInHours := time.Duration(24 * validForDays)
	notBefore := time.Now()
	notAfter := notBefore.Add(daysInHours * time.Hour)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     altDNSNames,
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func TestValidateInput(t *testing.T) {
	var msg map[string]interface{}
	var ok bool
	var args []string
	var text, expected string

	args = []string{"cmdName"}
	msg, ok = validateInput(args, 30)
	expected = "wrong number of arguments: expected 1 received 0"
	if ok || msg["err"] != expected {
		t.Error("Empty args should make validateInput fail with ->", expected)
	}

	args = []string{"cmdName", "", ""}
	msg, ok = validateInput(args, 0)
	expected = "wrong number of arguments: expected 1 received 2"
	if ok || msg["err"] != expected {
		t.Error("Empty args should make validateInput fail with ->", expected)
	}

	text = "not a json"
	args = []string{"cmdName", text}
	msg, ok = validateInput(args, 30)
	if ok || msg["err"] == nil {
		t.Error("validate fails if input is not json marshable")
	}

	text = `{"something":"wrong"}`
	args = []string{"cmdName", text}
	msg, ok = validateInput(args, 30)
	expected = "malformed request: missing host string"
	if ok || msg["err"] != expected {
		t.Error("host key is mandatory")
	}

	text = `{"days":"10"}`
	args = []string{"cmdName", text}
	msg, ok = validateInput(args, 10)
	expected = "malformed request: missing host string"
	if ok || msg["err"] != expected {
		t.Error("host key is mandatory")
	}

	text = `{"host":"ok","days":"notAnInteger"}`
	args = []string{"cmdName", text}
	_, ok = validateInput(args, 0)
	if ok {
		t.Error("should fail if days key string is not parsable to int")
	}

	text = `{"host":"ok","days":0}`
	args = []string{"cmdName", text}
	_, ok = validateInput(args, 123)
	if ok {
		t.Error("should fail if days key is not in string format")
	}

	text = `{"days":"1234","host":"someHost"}`
	args = []string{"cmdName", text}
	msg, ok = validateInput(args, 0)
	if !ok || msg["daysTolerance"] != 1234 || msg["host"] != "someHost" {
		t.Error("something wrong validating", text, "received", msg)
	}
}

func TestHostInCert(t *testing.T) {
	var domain, host, wild string
	var cert *x509.Certificate
	var validForDays = 30

	f := func(h string, c *x509.Certificate) {
		if !hostInCert(h, c) {
			t.Errorf("%s should be a valid host string", h)
		}
	}

	domain = "somethingstrange.com"
	host = "www." + domain
	wild = "*." + domain
	cert, _ = mockCert(host, []string{wild, domain}, validForDays)
	if hostInCert("bogus.com", cert) {
		t.Error("bogus domain should not be a valid host string")
	}
	for _, h := range []string{domain, host, wild} {
		f(h, cert)
	}

	domain = "why.not.some.more.levels.com."
	host = "www." + domain
	wild = "*." + domain
	cert, _ = mockCert(host, []string{wild, domain}, validForDays)
	for _, h := range []string{domain, host, wild} {
		f(h, cert)
	}
}

func TestParsedMsg(t *testing.T) {
	out := parsedMsg(map[string]interface{}{"msg": "notajson"})
	if out != `{"msg":"notajson"}` {
		t.Error("failed unmarshaling map")
	}
}

func TestValidateSSL(t *testing.T) {
	var msg, out map[string]interface{}
	var delta int
	var cert *x509.Certificate
	var expected, host, hostAlt string
	var validHosts []string

	// SSL cert created by mockCert is expiring in 30 days minus a few nanoseconds,
	// so the expected output form our API will be 29 days
	host = "some.host.here.com"
	hostAlt = "*.another.wildcard.domain"
	validHosts = []string{host, hostAlt, "another.unrelated.com", "whatever.else."}
	sort.Strings(validHosts)
	delta = 30
	cert, _ = mockCert(host, validHosts, delta)
	msg, _ = validateInput([]string{"command", `{"host":"` + host + `"}`}, delta)
	out = validateSSL(msg, cert)
	if out["alert"] == nil || out["alert"] != true {
		t.Error("check must fail when days left are smaller then delta, received", out)
	}
	if out["daysLeft"] == nil || out["daysLeft"] != delta-1 {
		t.Errorf("daysLeft must be %d, received %s", delta-1, out)
	}
	if out["host"] == nil || out["host"] != host {
		t.Error("host must be", host, "received", out)
	}
	if out["daysTolerance"] == nil || out["daysTolerance"] != delta {
		t.Error("daysTolerance must be default of ", delta, "received", out)
	}
	if out["notAfter"] == nil {
		t.Error("notAfter key must be present:", out)
	}
	expected = fmt.Sprintf("SSL certificate for %s will expire in %d days", host, 29)
	if out["response"] == nil || out["response"] != expected {
		t.Error("expected", expected, "have", out["response"])
	}
	if !reflect.DeepEqual(out["validHosts"], validHosts) {
		t.Errorf("#validHosts: want %s got %s", validHosts, out["validHosts"])
	}
	if out["issuedBy"] == nil || out["issuedBy"] != "" {
		t.Error("issuedBy not found in keys")
	}

	// this time we check the DNSAlt section, and we use a smaller delta, so
	// it should not alert
	host = "www.another.wildcard.domain"
	delta = 29
	msg, _ = validateInput([]string{"command", fmt.Sprintf(`{"host":"%s","days":"%d"}`, host, delta)}, 0)
	out = validateSSL(msg, cert)
	if out["alert"] != nil {
		t.Error("check must succeed when days left are bigger then delta,", out)
	}
	if out["daysLeft"] == nil || out["daysLeft"] != delta {
		t.Error("daysLeft must be 29, received", out)
	}
	if out["host"] == nil || out["host"] != host {
		t.Error("host must be", host, "received", out)
	}
	if out["daysTolerance"] == nil || out["daysTolerance"] != delta {
		t.Error("daysTolerance must be", delta, "received", out)
	}
	if out["notAfter"] == nil || out["response"] == nil {
		t.Error("both response and notAfter keys must be present:", out)
	}
	expected = fmt.Sprintf("SSL certificate for %s will expire in %d days", host, 29)
	if out["response"] == nil || out["response"] != expected {
		t.Error("expected", expected, "have", out["response"])
	}
	if !reflect.DeepEqual(out["validHosts"], validHosts) {
		t.Errorf("#validHosts: want %s got %s", validHosts, out["validHosts"])
	}

	host = "a.bogus.domain"
	msg, _ = validateInput([]string{"command", fmt.Sprintf(`{"host":"%s"}`, host)}, 0)
	out = validateSSL(msg, cert)
	expected = fmt.Sprintf("host %s not valid for the SSL certificate", host)
	if out["alert"] == nil || out["err"] == nil || out["err"] != expected {
		t.Error("validate should fail for", host, "received", out)
	}
}
