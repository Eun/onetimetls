package proto

import (
	"fmt"
	"io"

	"github.com/Eun/onetimetls/proto/internal"
)

type ProtoVersion interface {
	Write(writer io.Writer) error
	Read(reader io.Reader) error
}

var registeredProto map[uint16]ProtoVersion

func init() {
	registeredProto = make(map[uint16]ProtoVersion)
}

func RegisterProto(version uint16, handler ProtoVersion) error {
	if _, found := registeredProto[version]; found {
		return fmt.Errorf("%d already existent!", version)
	}
	registeredProto[version] = handler
	return nil
}

type Proto struct {
	Version uint16
	Data    ProtoVersion
}

func (p *Proto) Read(reader io.Reader) (err error) {
	p.Version, err = internal.ReadUInt16(reader)
	if err != nil {
		return err
	}

	var found bool
	p.Data, found = registeredProto[p.Version]
	if p.Data == nil || !found {
		return fmt.Errorf("invalid version %d", p.Version)
	}
	return p.Data.Read(reader)
}

func (p *Proto) Write(writer io.Writer) error {
	// write version
	if err := internal.WriteUInt16(writer, p.Version); err != nil {
		return err
	}
	return p.Data.Write(writer)
}
