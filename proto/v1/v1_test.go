package v1

import (
	"bytes"
	"reflect"
	"testing"
)

func TestProto(t *testing.T) {
	protoWrite := ProtoV1{
		EncryptedKey: []byte("KEY"),
		Certificate:  []byte("CERT"),
	}
	var buf bytes.Buffer
	if err := protoWrite.Write(&buf); err != nil {
		t.Fatal(err)
	}

	var protoRead ProtoV1
	if err := protoRead.Read(&buf); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(protoWrite, protoRead) {
		t.Fatalf("Expected %#v got %#v", protoWrite, protoRead)
	}
}
