package proto_test

import (
	"bytes"
	"testing"

	"reflect"

	"github.com/Eun/onetimetls/proto"
	v1 "github.com/Eun/onetimetls/proto/v1"
)

func TestProto(t *testing.T) {
	protoWrite := proto.Proto{
		Version: 1,
		Data: &v1.ProtoV1{
			EncryptedKey: []byte("KEY"),
			Certificate:  []byte("CERT"),
		},
	}
	var buf bytes.Buffer
	if err := protoWrite.Write(&buf); err != nil {
		t.Fatal(err)
	}

	var protoRead proto.Proto
	if err := protoRead.Read(&buf); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(protoWrite, protoRead) {
		t.Fatalf("Expected %#v got %#v", protoWrite, protoRead)
	}
}
