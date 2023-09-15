package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	listener, err := net.ListenPacket("udp", "0.0.0.0:8390")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for {
		buf := make([]byte, 1024)
		n, addr, err := listener.ReadFrom(buf)
		if err != nil {
			fmt.Println(err)
			continue
		}
		req := buf[:n]
		fmt.Println(addr)
		hostname, _ := os.Hostname()
		resp := fmt.Sprintf("I'm udp server running on %s, you have request for %s, and your address is: %s", hostname, string(req), addr)
		_, _ = listener.WriteTo([]byte(resp), addr)
	}
}
