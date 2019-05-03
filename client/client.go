package client

import (
	"context"
	"fmt"
	"net"

	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	"github.com/Eun/onetimetls/proto"
	"github.com/Eun/onetimetls/proto/v1"
	"github.com/pkg/errors"
)

type Client struct {
	Secret                []byte
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

func (c *Client) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	var p proto.Proto
	if err := p.Read(conn); err != nil {
		return nil, err
	}

	switch v := p.Data.(type) {
	case *v1.ProtoV1:
		return c.handleProtoV1(conn, v)
	default:
		return nil, errors.New("invalid proto version")
	}
}

func (c *Client) handleProtoV1(conn net.Conn, p *v1.ProtoV1) (net.Conn, error) {
	var keyPEMBlock []byte

	block, rest := pem.Decode(p.EncryptedKey)
	if len(rest) > 0 {
		return nil, fmt.Errorf("decrypt failed: extra data included in the key")
	}

	if x509.IsEncryptedPEMBlock(block) {
		var err error
		block.Bytes, err = x509.DecryptPEMBlock(block, c.Secret)
		if err != nil {
			return nil, fmt.Errorf("decrypt failed: %v", err)
		}
		keyPEMBlock = pem.EncodeToMemory(block)
	} else {
		keyPEMBlock = p.EncryptedKey
	}

	cert, err := tls.X509KeyPair(p.Certificate, keyPEMBlock)
	if err != nil {
		return nil, err
	}

	return tls.Client(conn, &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: c.VerifyPeerCertificate,
		MinVersion:            tls.VersionTLS12,
	}), nil
}
