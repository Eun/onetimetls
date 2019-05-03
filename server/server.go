package server

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"

	"crypto"

	"github.com/Eun/go-timebox"
	"github.com/Eun/onetimetls/proto/v1"
)

const Version = 1

type EncryptKeyFunc func(net.Conn) (secret []byte, cipher x509.PEMCipher, err error)

type TimeoutHitError struct{}

func (TimeoutHitError) Error() string {
	return "timeout hit"
}

type Server struct {
	Timeout     time.Duration
	EncryptKey  EncryptKeyFunc
	Certificate *tls.Certificate
	Listener    net.Listener
}

// Accept waits for and returns the next connection to the listener.
func (s *Server) Accept() (net.Conn, error) {
	if s.Certificate == nil {
		cert, err := MakeCert(time.Duration(24 * time.Hour))
		if err != nil {
			return nil, err
		}
		s.Certificate = &cert
	}
	if s.Timeout == 0 {
		s.Timeout = time.Duration(time.Second * 30)
	}
	conn, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return s.handleConnection(conn)
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (s *Server) Close() error {
	return s.Listener.Close()
}

// Addr returns the listener's network address.
func (s *Server) Addr() net.Addr {
	return s.Listener.Addr()
}

func (s *Server) handleConnection(conn net.Conn) (net.Conn, error) {
	cert, err := MakeCert(s.Timeout)
	if err != nil {
		return nil, err
	}

	keyPEMBlock, err := s.getPrivatePemBlock(conn, cert.PrivateKey)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	certPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	caPool.AppendCertsFromPEM(certPEMBlock)

	if err = v1.WriteFull(conn, &v1.ProtoV1{Certificate: certPEMBlock, EncryptedKey: keyPEMBlock}); err != nil {
		return nil, err
	}

	tlsConn := tls.Server(conn, &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{*s.Certificate},
		MinVersion:   tls.VersionTLS12,
		ClientCAs:    caPool,
	})
	returns, err := timebox.Timebox(s.Timeout, tlsConn.Handshake)
	if err != nil {
		// forcefully close this connection
		_ = conn.Close()
		if timebox.IsTimeoutError(err) {
			return nil, TimeoutHitError{}
		}
		return nil, err
	}

	if returns[0] != nil {
		return nil, returns[0].(error)
	}
	return tlsConn, nil
}

func (s *Server) getPrivatePemBlock(conn net.Conn, key crypto.PrivateKey) ([]byte, error) {
	privateBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if s.EncryptKey == nil {
		return pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateBytes,
		}), nil
	}
	secret, cipher, err := s.EncryptKey(conn)
	if err != nil {
		return nil, err
	}
	pemBlock, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", privateBytes, secret, cipher)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(pemBlock), nil
}

func MakeCert(timeout time.Duration) (cert tls.Certificate, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return cert, err
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return cert, err
	}

	var notBefore time.Time
	notBefore = time.Now()
	notAfter := notBefore.Add(timeout)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return cert, err
	}
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return cert, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	cert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return cert, err
	}

	if len(cert.Certificate) <= 0 {
		return cert, errors.New("no certificates present")
	}
	return cert, nil
}

func IsTimeoutHitError(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(TimeoutHitError)
	return ok
}
