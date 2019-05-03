package onetimetls

import (
	"bytes"
	"crypto/x509"
	"io/ioutil"
	"net"
	"sync"
	"testing"

	"time"

	"encoding/pem"

	"io"

	"crypto/tls"

	"bou.ke/monkey"
	"github.com/Eun/onetimetls/client"
	"github.com/Eun/onetimetls/server"
)

func Password(password string) func(net.Conn) (secret []byte, cipher x509.PEMCipher, err error) {
	return func(net.Conn) (secret []byte, cipher x509.PEMCipher, err error) {
		return []byte(password), x509.PEMCipherAES256, nil
	}
}

func TestIO(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	readBytes := make(chan []byte)
	go func() {
		s := server.Server{
			EncryptKey: Password("Hello World"),
			Listener:   listener,
		}
		conn, err := s.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		var bytes []byte
		bytes, err = ioutil.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}
		readBytes <- bytes
	}()

	client := client.Client{
		Secret: []byte("Hello World"),
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
		},
	}
	conn, err := client.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	want := []byte("Hello World")
	if _, err = conn.Write(want); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	got := <-readBytes

	if !bytes.Equal(got, want) {
		t.Fatalf("Expected %v, got %v", want, got)
	}
}

func TestInvalidSecret(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		s := server.Server{
			EncryptKey: Password("Hello World"),
			Listener:   listener,
		}
		s.Accept()
	}()

	client := client.Client{
		Secret: []byte("123"),
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
		},
	}
	_, err = client.Dial("tcp", listener.Addr().String())
	if err == nil {
		t.Fatal("wanted error")
	}
	if err.Error() != "decrypt failed: x509: decryption password incorrect" {
		t.Fatalf("got invalid error (%v)", err)
	}
}

func TestTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	serverHit := make(chan struct{})
	go func() {
		s := server.Server{
			Timeout:    time.Second,
			EncryptKey: Password("Hello World"),
			Listener:   listener,
		}
		_, err := s.Accept()
		if !server.IsTimeoutHitError(err) {
			t.Fatal(err)
		}
		serverHit <- struct{}{}
	}()

	hitPatch := false
	var guard *monkey.PatchGuard
	guard = monkey.Patch(x509.IsEncryptedPEMBlock, func(b *pem.Block) bool {
		hitPatch = true
		time.Sleep(time.Second * 3)
		guard.Unpatch()
		ok := x509.IsEncryptedPEMBlock(b)
		guard.Restore()
		return ok
	})

	client := client.Client{
		Secret: []byte("Hello World"),
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
		},
	}
	conn, err := client.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	want := []byte("Hello World")
	if _, err = conn.Write(want); err != io.EOF {
		t.Fatalf("Expected %v but got %v", io.EOF, err)
	}

	<-serverHit
	if !hitPatch {
		t.Fatalf("Did not hit patch")
	}
}

func TestInvalidClientCertificate(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	serverHit := make(chan struct{})
	go func() {
		s := server.Server{
			EncryptKey: Password("Hello World"),
			Listener:   listener,
		}
		_, err := s.Accept()
		if err == nil {
			t.Fatal("expected error")
		}
		serverHit <- struct{}{}
	}()

	newCert, err := server.MakeCert(time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	hitPatch := false
	var guard *monkey.PatchGuard
	guard = monkey.Patch(tls.Client, func(conn net.Conn, config *tls.Config) *tls.Conn {
		guard.Unpatch()
		defer guard.Restore()

		config.Certificates[0] = newCert
		hitPatch = true
		return tls.Client(conn, config)
	})

	client := client.Client{
		Secret: []byte("Hello World"),
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
		},
	}
	conn, err := client.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	<-serverHit

	if !hitPatch {
		t.Fatalf("Did not hit patch")
	}
}
