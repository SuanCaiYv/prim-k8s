package main

import (
	"io"
	"net"
	"os"
	"strconv"
)

func main() {
	targetIP := os.Getenv("TARGET_IP")
	targetPort0 := os.Getenv("TARGET_PORT")
	protocol := os.Getenv("PROTOCOL")
	bindPort := 8190
	targetPort, _ := strconv.Atoi(targetPort0)
	if protocol == "TCP" {
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{
			IP:   net.IPv4zero,
			Port: bindPort,
		})
		if err != nil {
			panic(err)
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				panic(err)
			}
			go func() {
				targetConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
					IP:   net.ParseIP(targetIP),
					Port: targetPort,
				})
				if err != nil {
					panic(err)
				}
				go forward(conn, targetConn)
				go forward(targetConn, conn)
			}()
		}
	} else {
		listener, err := net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: bindPort,
		})
		if err != nil {
			panic(err)
		}
		targetConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
			IP:   net.ParseIP(targetIP),
			Port: targetPort,
		})
		if err != nil {
			panic(err)
		}
		go forward(listener, targetConn)
		forward(targetConn, listener)
	}
}

func forward(reader io.Reader, writer io.Writer) {
	io.Copy(writer, reader)
}
