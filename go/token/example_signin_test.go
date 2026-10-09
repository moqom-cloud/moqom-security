// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package token_test

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/moqom-cloud/moqom-security/go/proof"
	"github.com/moqom-cloud/moqom-security/go/token"
)

// Replace an app's bearer session tokens with device-bound, post-quantum
// ones. The device enrols its public key once; every request then carries a
// fifteen-minute token naming that key and a fresh single-use proof, bound to
// the token and to the certificate of the server the device is talking to.
func Example_deviceBoundSignIn() {
	// ---- Your backend ----

	// The issuer key. Generate it once and keep issuer.Seed() in your secret
	// manager; publish issuer.PublicKey().JWK() for anything else that verifies.
	issuer, err := token.GenerateSigner()
	if err != nil {
		log.Fatal(err)
	}
	issuer = issuer.WithID("2026-10")
	verifier := token.NewVerifier("https://api.example.com", issuer.PublicKey()).ForTenant("acme")
	checker, err := proof.NewChecker(proof.NewDefaultMemoryNonceStore(),
		proof.WithAlgorithms(proof.MLDSA65), proof.WithCertificateRequired(true))
	if err != nil {
		log.Fatal(err)
	}

	// The server's TLS certificate, and its SHA-256, known before it serves.
	certificate, err := throwawayCertificate()
	if err != nil {
		log.Fatal(err)
	}
	certificateHash := sha256.Sum256(certificate.Certificate[0])

	mux := http.NewServeMux()
	// Enrolment: after your existing sign-in, the device sends its public key.
	mux.HandleFunc("POST /enrol", func(w http.ResponseWriter, r *http.Request) {
		user := "ada" // whoever your existing sign-in authenticated
		var key proof.JWK
		if err := json.NewDecoder(r.Body).Decode(&key); err != nil {
			http.Error(w, "bad key", http.StatusBadRequest)
			return
		}
		thumbprint, err := key.Thumbprint() // derived here, never taken from the device
		if err != nil {
			http.Error(w, "bad key", http.StatusBadRequest)
			return
		}
		now := time.Now()
		jws, err := issuer.Sign(token.Claims{
			Issuer:       "https://api.example.com",
			Subject:      user,
			Tenant:       "acme",
			ID:           proof.NewNonce(),
			IssuedAt:     now.Unix(),
			Expires:      now.Add(15 * time.Minute).Unix(),
			Confirmation: token.Confirmation{Thumbprint: thumbprint},
		})
		if err != nil {
			http.Error(w, "cannot mint", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, jws)
	})
	// Every other request: verify the token, then the proof.
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		jws := strings.TrimPrefix(r.Header.Get("Authorization"), "MOQT ")
		now := time.Now()
		claims, err := verifier.Verify(jws, now)
		if err != nil {
			http.Error(w, token.Class(err), http.StatusUnauthorized)
			return
		}
		err = checker.Check([]byte(r.Header.Get("MOQT-Proof")), []byte(jws), certificateHash[:],
			claims.Confirmation.Thumbprint, now, claims.ExpiresTime())
		if err != nil {
			http.Error(w, proof.Class(err), http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "hello %s", claims.Subject)
	})
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)

	// ---- The device ----

	// On iOS this key is made in the Secure Enclave and never leaves it.
	device, err := proof.GenerateProver(proof.MLDSA65)
	if err != nil {
		log.Fatal(err)
	}
	key, err := json.Marshal(device.JWK())
	if err != nil {
		log.Fatal(err)
	}
	enrol, err := http.NewRequest("POST", "https://"+server.Listener.Addr().String()+"/enrol", bytes.NewReader(key))
	if err != nil {
		log.Fatal(err)
	}
	_, jws := send(server.Listener.Addr().String(), roots, enrol, nil)

	// A request with the token and a proof for the certificate this
	// connection's server presented.
	var sent []byte
	me := func(jws string, sign func(certificateHash []byte) []byte) string {
		request, err := http.NewRequest("GET", "https://"+server.Listener.Addr().String()+"/me", nil)
		if err != nil {
			log.Fatal(err)
		}
		request.Header.Set("Authorization", "MOQT "+jws)
		status, body := send(server.Listener.Addr().String(), roots, request, func(certificateHash []byte) {
			sent = sign(certificateHash)
			request.Header.Set("MOQT-Proof", string(sent))
		})
		return fmt.Sprint(status, " ", body)
	}
	prove := func(certificateHash []byte) []byte {
		p, err := device.Prove([]byte(jws), certificateHash, proof.NewNonce(), time.Now())
		if err != nil {
			log.Fatal(err)
		}
		return p
	}

	fmt.Println(me(jws, prove))

	// Someone who copies the request and sends it again.
	captured := sent
	fmt.Println(me(jws, func([]byte) []byte { return captured }))

	// Someone who steals the token and proves with their own key.
	thief, err := proof.GenerateProver(proof.MLDSA65)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(me(jws, func(certificateHash []byte) []byte {
		p, _ := thief.Prove([]byte(jws), certificateHash, proof.NewNonce(), time.Now())
		return p
	}))

	// A machine in the middle with its own certificate, even one a CA issued
	// for your name, forwarding what the device sent it.
	middle := sha256.Sum256([]byte("the interceptor's certificate"))
	fmt.Println(me(jws, func([]byte) []byte { return prove(middle[:]) }))

	// The token alone, as a bearer token.
	fmt.Println(me(jws, func([]byte) []byte { return nil }))

	// Output:
	// 200 hello ada
	// 401 replayed
	// 401 wrong_key
	// 401 wrong_certificate
	// 401 malformed
}

// send makes one request on its own TLS connection. sign, when set, runs after
// the handshake with the SHA-256 of the certificate the server presented, so a
// proof names exactly the peer the request goes to.
func send(addr string, roots *x509.CertPool, request *http.Request, sign func(certificateHash []byte)) (int, string) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	if sign != nil {
		leaf := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw)
		sign(leaf[:])
	}
	if err := request.Write(conn); err != nil {
		log.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	return response.StatusCode, strings.TrimSpace(string(body))
}

// throwawayCertificate stands in for the server's real certificate.
func throwawayCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
