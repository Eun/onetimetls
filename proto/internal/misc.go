package internal

import (
	"encoding/binary"
	"fmt"
	"io"
)

func WriteUInt16(writer io.Writer, i uint16) error {
	var buffer [2]byte
	binary.LittleEndian.PutUint16(buffer[:], i)
	n, err := writer.Write(buffer[:])
	if err != nil {
		return err
	}
	if n != 2 {
		return fmt.Errorf("expected 2 got %d bytes", n)
	}
	return nil
}

func WriteUInt32(writer io.Writer, i uint32) error {
	var buffer [4]byte
	binary.LittleEndian.PutUint32(buffer[:], i)
	n, err := writer.Write(buffer[:])
	if err != nil {
		return err
	}
	if n != 4 {
		return fmt.Errorf("expected 4 got %d bytes", n)
	}
	return nil
}

func ReadUInt16(reader io.Reader) (uint16, error) {
	var buffer [2]byte
	n, err := reader.Read(buffer[:])
	if err != nil {
		return 0, fmt.Errorf("expected 2 got %d bytes", n)
	}
	return binary.LittleEndian.Uint16(buffer[:]), nil
}

func ReadUInt32(reader io.Reader) (uint32, error) {
	var buffer [4]byte
	n, err := reader.Read(buffer[:])
	if err != nil {
		return 0, fmt.Errorf("expected 4 got %d bytes", n)
	}
	return binary.LittleEndian.Uint32(buffer[:]), nil
}
