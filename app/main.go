package main

import (
	"fmt"
	"net"
)

func main() {
	test()

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

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := buf[:size]
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, string(receivedData))

		response := DNSReply{}
		response.DNSHeader = StaticDNSHeader()
		response.DNSHeader.Flags |= (1 << 15) // set QR bit to 1 to indicate a DNS reply
		response.DNSQuestions = []DNSQuestion{*StaticDNSQuestion()}

		respBytes := response.Encode()

		_, err = udpConn.WriteToUDP(respBytes, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
