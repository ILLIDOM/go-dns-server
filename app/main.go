package main

import (
	"flag"
	"fmt"
	"net"
)

func main() {
	// get --resolver argument as flag
	var resolverArg string
	flag.StringVar(&resolverArg, "resolver", "8.8.8.8:53", "ip:port of the DNS server requests are forwarded to")
	flag.Parse()

	fmt.Printf("resolver is set to: %s\n", resolverArg)

	fmt.Println("starting UDP server...")
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	fmt.Println("listening on port 2053")

	buf := make([]byte, 512)

	// create a DNS resolver
	resolver := NewResolver(resolverArg)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := buf[:size]
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, string(receivedData))

		// parse the original message
		message := &DNSMessage{}
		message.Decode(receivedData)

		fmt.Printf("using resolver: %s\n", resolverArg)
		// resolve the dns query
		response, err := resolver.Resolve(message)
		if err != nil {
			fmt.Printf("error creating response: %v\n", err)
		}

		// encode the dns response to bytes
		respBytes := response.Encode()

		_, err = udpConn.WriteToUDP(respBytes, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
