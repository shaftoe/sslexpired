package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const version = "0.1.0"

// SSLCerts returns a slice of x509 Certificates available at the
// target hostname
func SSLCerts(host string) ([]*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", conf)
	if err != nil {
		return nil, err
	}
	conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

func validateInput(args []string, delta int) (map[string]interface{}, bool) {
	msg := make(map[string]interface{})

	// native OpenWhisk actions receive one argument, the JSON object as a string
	if len(args) != 2 {
		msg["err"] = fmt.Sprintf("wrong number of arguments: "+
			"expected 1 received %d", (len(args) - 1))
		return msg, false
	}

	// unmarshal the string to a JSON object
	var obj map[string]interface{}
	err := json.Unmarshal([]byte(args[1]), &obj)
	if err != nil {
		msg["err"] = err.Error()
		return msg, false
	}

	// host parameter IS mandatory
	host, ok := obj["host"].(string)
	if !ok || host == "" {
		msg["err"] = "malformed request: missing host string"
		return msg, false
	}
	msg["host"] = host

	// days parameter is not mandatory, we use default if not present
	days, ok := obj["days"]
	if ok {
		switch days.(type) {
		case string:
			d, err := strconv.Atoi(days.(string))
			if err != nil {
				msg["err"] = "failed to parse days parameter: " + err.Error()
				return msg, false
			}
			msg["daysTolerance"] = d
		default:
			msg["err"] = fmt.Sprintf("days parameter malformatted: %T, must be string", days)
			return msg, false
		}
	} else {
		msg["daysTolerance"] = delta
	}

	return msg, true
}

func daysLeft(cert *x509.Certificate) float64 {
	return cert.NotAfter.Sub(time.Now()).Hours() / 24
}

func matchFound(host string, cert *x509.Certificate) bool {
	if cert.Subject.CommonName == host {
		return true
	}
	for _, name := range cert.DNSNames {
		if host == name {
			return true
		}
	}
	return false
}

func allCertHosts(cert *x509.Certificate) []string {
	set := map[string]struct{}{}
	set[cert.Subject.CommonName] = struct{}{}
	for _, name := range cert.DNSNames {
		set[name] = struct{}{}
	}

	var hosts []string
	for name := range set {
		hosts = append(hosts, name)
	}
	sort.Strings(hosts)

	return hosts
}

func hostInCert(host string, cert *x509.Certificate) bool {
	if matchFound(host, cert) {
		return true
	}

	// if exact match for host is not found, we search for a wildcard
	// replacing the first part of the hostname with *
	splitted := strings.Split(host, ".")
	if len(splitted) > 2 {
		splitted[0] = "*"
		return matchFound(strings.Join(splitted, "."), cert)
	}

	return false
}

func parsedMsg(msg map[string]interface{}) string {
	resp, err := json.Marshal(msg)
	if err != nil {
		return fmt.Sprintf(`{"err":"%s"}`, err)
	}
	return fmt.Sprint(string(resp))
}

func validateSSL(msg map[string]interface{}, cert *x509.Certificate) map[string]interface{} {
	dLeft := daysLeft(cert)
	msg["daysLeft"] = int(dLeft) // we round the number to biggest integer
	msg["response"] = fmt.Sprintf("SSL certificate for %s will expire in %d days",
		msg["host"], msg["daysLeft"])
	msg["notAfter"] = cert.NotAfter.String()
	msg["validHosts"] = allCertHosts(cert)

	if dLeft < float64(msg["daysTolerance"].(int)) {
		msg["alert"] = true
	}

	if !hostInCert(msg["host"].(string), cert) {
		msg["alert"] = true
		msg["err"] = fmt.Sprintf("host %s not valid for the SSL certificate", msg["host"])
	}

	return msg
}

func main() {
	msg, ok := validateInput(os.Args, 30)
	if !ok {
		fmt.Println(parsedMsg(msg))
		return
	}
	certs, err := SSLCerts(msg["host"].(string))
	if err != nil {
		delete(msg, "daysTolerance")
		msg["err"] = err.Error()
		fmt.Println(parsedMsg(msg))
		return
	}
	if len(certs) == 0 {
		msg["err"] = "certificates list is empty"
		fmt.Println(parsedMsg(msg))
		return
	}
	// We check only the first certificate in the chain
	fmt.Println(parsedMsg(validateSSL(msg, certs[0])))
}
