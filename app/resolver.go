package main

import (
	"fmt"
	"net"
	"strings"
)

type Resolver struct {
	IP   net.IP
	Port string
}

func NewResolver(address string) *Resolver {
	ipPort := strings.Split(address, ":")

	// minimal error handling improve by checking validity of IP and port
	if len(ipPort) != 2 {
		fmt.Printf("error parsing resolver: %s\n", address)
	}
	ip := net.ParseIP(ipPort[0])
	if ip == nil {
		fmt.Printf("error parsing IP address: %s\n", ipPort[0])
	}

	return &Resolver{
		IP:   ip,
		Port: ipPort[1],
	}
}

// ResolveLocally resolved a DNS query locally without forwaring it
func (r *Resolver) ResolveLocally(msg *DNSMessage) (*DNSMessage, error) {
	resp := &DNSMessage{}
	resp.Header = msg.Header
	// set QR flag to indicate a dns reply
	resp.Header.Flags.QR = 1
	// if the OPCODE is not 0 (indicating a non-standard query), the RCODE is set to 4, which means "Not Implemented".
	if msg.Header.Flags.OPCODE != 0 {
		resp.Header.Flags.RCODE = 4
	}
	resp.Questions = msg.Questions
	resp.Answers = CreateDNSAnswers(resp.Questions)
	resp.Header.ANCOUNT = uint16(len(resp.Answers))
	return resp, nil
}

// Resolve forwards DNS queries to the resolver - splitting questions into multiple queries but returns a single message
// containing all answers
func (r *Resolver) Resolve(msg *DNSMessage) (*DNSMessage, error) {
	var answers []*Answer

	// if msg contains multiple questions they need to send as individual DNS queries to the resolver
	// create DNS messages for each question
	// TODO: improve by sending queries to the reolver concurrently
	for _, question := range msg.Questions {
		dnsQuery := &DNSMessage{
			Header:    msg.Header,
			Questions: []*Question{question},
		}
		// only one question is sent per query
		dnsQuery.Header.QDCOUNT = 1

		// send query
		respBytes, err := r.sendQuery(dnsQuery.Encode())
		if err != nil {
			fmt.Printf("error sending query to resolver: %v", err)
		}

		// extract Answer from response
		respMsg := &DNSMessage{}
		respMsg.Decode(respBytes)
		answer := respMsg.Answers
		answers = append(answers, answer...)
	}

	// create final responseMessage
	finalResponse := &DNSMessage{
		Header:    msg.Header,
		Questions: msg.Questions,
		Answers:   answers,
	}

	// if the OPCODE is not 0 (indicating a non-standard query), the RCODE is set to 4, which means "Not Implemented".
	if finalResponse.Header.Flags.OPCODE != 0 {
		finalResponse.Header.Flags.RCODE = 4
	}

	// set QR flag to 1 to indicate a DNS reply
	finalResponse.Header.Flags.QR = 1
	// adjust the qustion count (needed because finalResponse points to the original message which was altered
	// by setting the QDCOUNT to 1 when sending the request towards the resolver
	finalResponse.Header.QDCOUNT = uint16(len(finalResponse.Questions))

	// set the correct answer count
	finalResponse.Header.ANCOUNT = uint16(len(finalResponse.Answers))

	return finalResponse, nil
}

func (r *Resolver) sendQuery(data []byte) ([]byte, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", r.IP.String(), r.Port))
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 512)
	size, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}

	return buffer[:size], nil
}
