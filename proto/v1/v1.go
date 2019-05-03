package v1

import (
	"bufio"
	"bytes"
	"fmt"
	"io"

	"github.com/Eun/onetimetls/proto"
	"github.com/Eun/onetimetls/proto/internal"
	"github.com/vmihailenco/msgpack"
)

type ProtoV1 struct {
	Certificate  []byte
	EncryptedKey []byte
}

func init() {
	if err := proto.RegisterProto(1, &ProtoV1{}); err != nil {
		panic(err)
	}
}

func (p *ProtoV1) Write(writer io.Writer) error {
	var buf bytes.Buffer

	// write data into the buffer
	if err := msgpack.NewEncoder(&buf).Encode(p); err != nil {
		return err
	}

	w := bufio.NewWriter(writer)
	// write size
	if err := internal.WriteUInt32(w, uint32(buf.Len())); err != nil {
		return err
	}
	// write the buffer
	n, err := w.Write(buf.Bytes())
	if err != nil {
		return err
	}
	if n != buf.Len() {
		return fmt.Errorf("expected %d got %d bytes", buf.Len(), n)
	}
	return w.Flush()
}

func (p *ProtoV1) Read(reader io.Reader) error {
	size, err := internal.ReadUInt32(reader)
	if err != nil {
		return err
	}

	return msgpack.NewDecoder(io.LimitReader(reader, int64(size))).Decode(p)
}

func WriteFull(writer io.Writer, p *ProtoV1) error {
	v := proto.Proto{
		Version: 1,
		Data:    p,
	}
	return v.Write(writer)
}
