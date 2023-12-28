package main

import "encoding/binary"

// some TYPE constants: https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
const (
	A     = 1
	NS    = 2
	CNAME = 5
	PTR   = 12
	MX    = 15
	TXT   = 16
)

type DNSReply struct {
	DNSHeader    *DNSHeader    // 12bytes
	DNSQuestions []DNSQuestion // length of DNSQuestion.Name + 4 Bytes (Type and Class) for each question
}

func (r *DNSReply) Encode() []byte {
	buf := r.DNSHeader.Encode()
	for _, dnsQuestion := range r.DNSQuestions {
		buf = append(buf, dnsQuestion.Encode()...)
	}

	return buf
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

type DNSQuestion struct {
	Name  []byte
	Type  uint16
	Class uint16
}

func (q *DNSQuestion) Encode() []byte {
	buf := q.Name
	binary.BigEndian.AppendUint16(buf, q.Type)
	binary.BigEndian.AppendUint16(buf, q.Class)
	return buf
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

// StaticDNSHeader returns a static header for testing purposes
func StaticDNSHeader() *DNSHeader {
	return &DNSHeader{
		ID:      1234,
		Flags:   0,
		QDCOUNT: 0,
		ANCOUNT: 0,
		NSCOUNT: 0,
		ARCOUNT: 0,
	}
}

// NewDNSHeader creates a DNS header based on the received header inside the DNS request
func NewDNSHeader(header []byte) *DNSHeader {
	id := binary.BigEndian.Uint16(header[0:2])
	qdcount := binary.BigEndian.Uint16(header[4:6])
	ancount := binary.BigEndian.Uint16(header[6:8])
	nscount := binary.BigEndian.Uint16(header[8:10])
	arcount := binary.BigEndian.Uint16(header[10:12])

	return &DNSHeader{
		ID:      id,
		Flags:   0,
		QDCOUNT: qdcount,
		ANCOUNT: ancount,
		NSCOUNT: nscount,
		ARCOUNT: arcount,
	}
}

// StaticDNSQuestion returns a static question for testing purpose
func StaticDNSQuestion() *DNSQuestion {
	return &DNSQuestion{
		Name:  []byte("\x0ccodecrafters\x02io\x00"),
		Type:  1,
		Class: 1,
	}
}

func NewDNSQuestion(body []byte) *DNSQuestion {
	return &DNSQuestion{}
}
