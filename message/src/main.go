package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/quic-go/quic-go"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	LogLevel string `toml:"log_level"`
	Server   struct {
		IpVersion      string `toml:"ip_version"`
		PublicService  bool   `toml:"public_service"`
		ClusterAddress string `toml:"cluster_address"`
		ServiceAddress string `toml:"service_address"`
		Domain         string `toml:"domain"`
		CertPath       string `toml:"cert_path"`
		KeyPath        string `toml:"key_path"`
		MaxConnections int    `toml:"max_connections"`
	} `toml:"server"`
	Transport struct {
		KeepAliveInterval     int64 `toml:"keep_alive_interval"`
		ConnectionIdleTimeout int64 `toml:"connection_idle_timeout"`
		MaxBiStreams          int64 `toml:"max_bi_streams"`
	} `toml:"transport"`
	Redis struct {
		Addresses []string `toml:"addresses"`
		Passwords []string `toml:"passwords"`
	} `toml:"redis"`
	Scheduler struct {
		Address  string `toml:"address"`
		Domain   string `toml:"domain"`
		CertPath string `toml:"cert_path"`
	} `toml:"scheduler"`
	Rpc struct {
		Scheduler struct {
			Address  string `toml:"address"`
			Domain   string `toml:"domain"`
			CertPath string `toml:"cert_path"`
		} `toml:"scheduler"`
		Api struct {
			Address  string `toml:"address"`
			Domain   string `toml:"domain"`
			CertPath string `toml:"cert_path"`
		} `toml:"api"`
	} `toml:"rpc"`
	Seqnum struct {
		CertPath string `toml:"cert_path"`
	} `toml:"seqnum"`
	MessageQueue struct {
		Address string `toml:"address"`
	} `toml:"message_queue"`
}

func (c *Config) String() string {
	return fmt.Sprintf(
		"LogLevel: %s\nServer: %v\nTransport: %v\nRedis: %v\nScheduler: %v\nRpc: %v\nSeqnum: %v\nMessageQueue: %v\n",
		c.LogLevel,
		c.Server,
		c.Transport,
		c.Redis,
		c.Scheduler,
		c.Rpc,
		c.Seqnum,
		c.MessageQueue,
	)
}

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	myId := os.Getenv("MY_ID")
	clusterIp := os.Getenv("CLUSTER_IP")
	serviceIp := os.Getenv("SERVICE_IP")
	clusterAddress := os.Getenv("CLUSTER_ADDRESS")
	serviceAddress := os.Getenv("SERVICE_ADDRESS")

	var config Config
	configPath = "./config.toml"
	_, err := toml.DecodeFile(configPath, &config)
	if err != nil {
		fmt.Println("decode toml failed:", err)
		return
	}
	if clusterIp != "" {
		list := strings.Split(config.Server.ClusterAddress, ":")
		config.Server.ClusterAddress = clusterIp + ":" + list[len(list)-1]
	}
	if serviceIp != "" {
		list := strings.Split(config.Server.ServiceAddress, ":")
		config.Server.ServiceAddress = serviceIp + ":" + list[len(list)-1]
	}
	if clusterAddress != "" {
		config.Server.ClusterAddress = clusterAddress
	}
	if serviceAddress != "" {
		config.Server.ServiceAddress = serviceAddress
	}

	cert, err := tls.LoadX509KeyPair(config.Server.CertPath, config.Server.KeyPath)
	if err != nil {
		fmt.Println("Error loading certificate:", err)
		return
	}

	certPool := x509.NewCertPool()
	certData, err := ioutil.ReadFile(config.Server.CertPath)
	if err != nil {
		fmt.Println("Error reading certificate file:", err)
		return
	}
	// Parse the certificate data
	block, _ := pem.Decode(certData)
	if block == nil {
		fmt.Println("Failed to parse PEM block containing certificate")
		return
	}
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing X.509 certificate:", err)
		return
	}
	certPool.AddCert(clientCert)

	tlsConfig := tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		NextProtos:         []string{"PRIM"},
		ClientCAs:          certPool,
	}

	quicConf := quic.Config{
		MaxIdleTimeout:        time.Millisecond * time.Duration(config.Transport.ConnectionIdleTimeout),
		MaxIncomingStreams:    config.Transport.MaxBiStreams,
		MaxIncomingUniStreams: config.Transport.MaxBiStreams,
		KeepAlivePeriod:       time.Millisecond * time.Duration(config.Transport.KeepAliveInterval),
		Allow0RTT:             true,
	}

	clusterParseList := strings.Split(config.Server.ClusterAddress, ":")
	clusterBindPort := clusterParseList[len(clusterParseList)-1]
	clusterBindAddress := ""
	if config.Server.PublicService {
		if config.Server.IpVersion == "v4" {
			clusterBindAddress = "0.0.0.0:" + clusterBindPort
		} else {
			clusterBindAddress = "[::]:" + clusterBindPort
		}
	} else {
		if config.Server.IpVersion == "v4" {
			clusterBindAddress = "127.0.0.1:" + clusterBindPort
		} else {
			clusterBindAddress = "[::1]:" + clusterBindPort
		}
	}

	serviceParseList := strings.Split(config.Server.ServiceAddress, ":")
	serviceBindPort := serviceParseList[len(serviceParseList)-1]
	serviceBindAddress := ""
	if config.Server.PublicService {
		if config.Server.IpVersion == "v4" {
			serviceBindAddress = "0.0.0.0:" + serviceBindPort
		} else {
			serviceBindAddress = "[::]:" + serviceBindPort
		}
	} else {
		if config.Server.IpVersion == "v4" {
			serviceBindAddress = "127.0.0.1:" + serviceBindPort
		} else {
			serviceBindAddress = "[::1]:" + serviceBindPort
		}
	}

	// tls server
	network1 := "tcp6"
	if config.Server.IpVersion == "v4" {
		network1 = "tcp4"
	}
	listener1, err := tls.Listen(network1, serviceBindAddress, &tlsConfig)
	if err != nil {
		fmt.Println("Error creating listener:", err)
		return
	}
	defer listener1.Close()
	go func() {
		for {
			conn, err := listener1.Accept()
			if err != nil {
				fmt.Println("Error accepting connection:", err)
				continue
			}
			defer conn.Close()
			go echoHandler(conn)
		}
	}()

	// scheduler connection
	schedulerConn, err := quic.DialAddr(context.Background(), config.Scheduler.Address, &tlsConfig, &quicConf)
	if err != nil {
		fmt.Println("Error dialing scheduler:", err)
		return
	}
	go func() {
		conn, err := schedulerConn.OpenStream()
		if err != nil {
			fmt.Println("Error opening stream:", err)
			return
		}
		conn.Write([]byte(fmt.Sprintf("%s %s", config.Server.ClusterAddress, myId)))
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				fmt.Println("Error reading from stream:", err)
				return
			}
			fmt.Println("scheduler says: ", string(buf[:n]))
		}
	}()

	// cluster server
	network3 := "udp6"
	if config.Server.IpVersion == "v4" {
		network3 = "udp4"
	}
	list3 := strings.Split(clusterBindAddress, ":")
	port3, err := strconv.Atoi(list3[len(list3)-1])
	udpConn, err := net.ListenUDP(network3, &net.UDPAddr{IP: net.ParseIP(clusterBindAddress[0 : len(clusterBindAddress)-len(list3[len(list3)-1])-1]), Port: port3})
	// ... error handling
	tr3 := quic.Transport{
		Conn: udpConn,
	}
	listener4, err := tr3.Listen(&tlsConfig, &quicConf)
	go func() {
		for {
			conn, err := listener4.Accept(context.Background())
			if err != nil {
				fmt.Println("Error accepting connection:", err)
				continue
			}
			go func() {
				for {
					rw, err := conn.AcceptStream(context.Background())
					if err != nil {
						fmt.Println("Error accepting stream:", err)
						continue
					}
					go echoHandler(rw)
				}
			}()
		}
	}()

	// quic server
	network4 := "udp6"
	if config.Server.IpVersion == "v4" {
		network4 = "udp4"
	}
	list4 := strings.Split(serviceBindAddress, ":")
	port4, err := strconv.Atoi(list4[len(list4)-1])
	udpConn, err = net.ListenUDP(network4, &net.UDPAddr{IP: net.ParseIP(serviceBindAddress[0 : len(serviceBindAddress)-len(list4[len(list4)-1])-1]), Port: port4})
	// ... error handling
	tr4 := quic.Transport{
		Conn: udpConn,
	}
	listener4, err = tr4.Listen(&tlsConfig, &quicConf)
	if err != nil {
		fmt.Println("Error creating listener:", err)
		return
	}
	for {
		conn, err := listener4.Accept(context.Background())
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go func() {
			for {
				rw, err := conn.AcceptStream(context.Background())
				if err != nil {
					fmt.Println("Error accepting stream:", err)
					continue
				}
				go echoHandler(rw)
			}
		}()
	}
}

func echoHandler(rw io.ReadWriter) {
	buf := make([]byte, 1024)
	for {
		n, err := rw.Read(buf)
		if err != nil {
			fmt.Println("Error reading from stream:", err)
			return
		}
		fmt.Println("Received:", string(buf[:n]))
		_, err = rw.Write(buf[:n])
		if err != nil {
			fmt.Println("Error writing to stream:", err)
			return
		}
	}
}
