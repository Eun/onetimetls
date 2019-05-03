package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
)

func Example() {
	// simple echo server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	s := Server{
		Listener: listener,
	}

	for {
		conn, err := s.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			defer conn.Close()
			reader := bufio.NewReader(conn)
			for {
				// read client request data
				bytes, err := reader.ReadBytes(byte('\n'))
				if err != nil {
					if err != io.EOF {
						fmt.Println("failed to read data, err:", err)
					}
					return
				}
				fmt.Printf("request: %s", bytes)

				line := fmt.Sprintf("Echo: %s", bytes)
				fmt.Printf("response: %s", line)
				conn.Write([]byte(line))
			}
		}()
	}
}
