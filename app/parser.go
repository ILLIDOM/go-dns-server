package main

import "encoding/binary"

type DNSReply struct {
	DNSHeader []byte // 12bytes
}

type DNSHeader struct {
	ID uint16 // 16bits -> A random ID assigned to query packets. Response packets must reply with the same ID.

	// Flags contains the 16bit long DNS header flags
	// QR      uint8  // 1bit -> 1 for a reply packet, 0 for a question packet.
	// OPCODE  uint8  // 4bit -> Specifies the kind of query in a message.
	// AA      uint8  // 1bit -> 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
	// TC      uint8  // 1bit -> 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
	// RD      uint8  // 1bit -> Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
	// RA      uint8  // 1bit -> Server sets this to 1 to indicate that recursion is available.
	// Z       uint8  // 3bit -> Used by DNSSEC queries. At inception, it was reserved for future use.
	// RCODE   uint8  // 4bit -> Response code indicating the status of the response.
	Flags uint16 // 16bits -> Flags

	QDCOUNT uint16 // 16bit -> Number of questions in the Question section.
	ANCOUNT uint16 // 16bit -> Number of records in the Answer section.
	NSCOUNT uint16 // 16bit -> Number of records in the Authority section.
	ARCOUNT uint16 // 16bit -> Number of records in the Additional section.
}

// Encode returns a 12byte long encoded DNS header
func (h *DNSHeader) Encode() []byte {
	buffer := make([]byte, 12)
	// write header into buffer
	binary.BigEndian.PutUint16(buffer[0:2], h.ID)
	binary.BigEndian.PutUint16(buffer[2:4], h.Flags)
	binary.BigEndian.PutUint16(buffer[4:6], h.QDCOUNT)
	binary.BigEndian.PutUint16(buffer[6:8], h.ANCOUNT)
	binary.BigEndian.PutUint16(buffer[8:10], h.NSCOUNT)
	binary.BigEndian.PutUint16(buffer[10:12], h.ARCOUNT)
	return buffer
}

func NewDNSHeader(header []byte) *DNSHeader {
	return &DNSHeader{
		ID:      1234,
		Flags:   0,
		QDCOUNT: 0,
		ANCOUNT: 0,
		NSCOUNT: 0,
		ARCOUNT: 0,
	}
}
