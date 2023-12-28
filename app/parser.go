package main

import "encoding/binary"

// some TYPE constants: https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
const (
	A            = 1
	NS           = 2
	CNAME        = 5
	PTR          = 12
	MX           = 15
	TXT          = 16
	TypeSize     = 2
	ClassSize    = 2
	TTLSize      = 4
	RDLengthSize = 2
)

type DNSReply struct {
	DNSHeader    *DNSHeader    // 12bytes
	DNSQuestions []DNSQuestion // length of DNSQuestion.Name + 4 Bytes (Type and Class) for each question
	DNSAnswers   []DNSAnswer   // length is variable due to the data field
}

// Encode returns the BigEndian encoded DNSReply as a byte array
func (r *DNSReply) Encode() []byte {
	// improve by creating a fixed size buffer first
	buf := r.DNSHeader.Encode()
	for _, dnsQuestion := range r.DNSQuestions {
		buf = append(buf, dnsQuestion.Encode()...)
	}

	for _, dnsAnswer := range r.DNSAnswers {
		buf = append(buf, dnsAnswer.Encode()...)
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

type DNSQuestion struct {
	Name  []byte // The domain name encoded as a sequence of labels.
	Type  uint16 // The query type according to: https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
	Class uint16 // The class according to: https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
}

func (q *DNSQuestion) Encode() []byte {
	// longer but not that many copies as with append
	size := len(q.Name) + TypeSize + ClassSize // add the size for the Type and Class fields
	buf := make([]byte, size)
	copy(buf, q.Name)
	offset := len(q.Name)
	binary.BigEndian.PutUint16(buf[offset:offset+TypeSize], q.Type)
	offset += TypeSize
	binary.BigEndian.PutUint16(buf[offset:offset+ClassSize], q.Class)
	binary.BigEndian.AppendUint16(buf, q.Type)

	// probably not as effective because the content needs to be copied twice
	// buf := q.Name
	// buf = binary.BigEndian.AppendUint16(buf, q.Type)
	// buf = binary.BigEndian.AppendUint16(buf, q.Class)

	return buf
}

type DNSAnswer struct {
	Name     []byte // The domain name encoded as a sequence of labels.
	Type     uint16 // The query type according to: https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
	Class    uint16 // The class according to: https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
	TTL      uint32 // The duration in seconds a record can be cached before requerying.
	RDLENGTH uint16 // Length of the RDATA field in bytes.
	RDATA    []byte // Data specific to the record type.
}

func (a *DNSAnswer) Encode() []byte {
	// add the size for the different fields
	size := len(a.Name) + TypeSize + ClassSize + TTLSize + RDLengthSize + int(a.RDLENGTH)
	buf := make([]byte, size)
	copy(buf, a.Name)
	offset := len(a.Name)
	binary.BigEndian.PutUint16(buf[offset:offset+TypeSize], a.Type)
	offset += TypeSize
	binary.BigEndian.PutUint16(buf[offset:offset+ClassSize], a.Class)
	offset += ClassSize
	binary.BigEndian.PutUint32(buf[offset:offset+TTLSize], a.TTL)
	offset += TTLSize
	binary.BigEndian.PutUint16(buf[offset:offset+RDLengthSize], a.RDLENGTH)
	offset += RDLengthSize
	copy(buf[offset:], a.RDATA)

	return buf
}

// StaticDNSHeader returns a static header for testing purposes
func StaticDNSHeader() *DNSHeader {
	return &DNSHeader{
		ID:      1234,
		Flags:   0,
		QDCOUNT: 1,
		ANCOUNT: 1,
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
		Type:  A,
		Class: 1,
	}
}

func NewDNSQuestion(body []byte) *DNSQuestion {
	return &DNSQuestion{}
}

func StaticDNSAnswer() *DNSAnswer {
	return &DNSAnswer{
		Name:     []byte("\x0ccodecrafters\x02io\x00"),
		Type:     A,
		Class:    1,
		TTL:      60,
		RDLENGTH: 4,
		RDATA:    []byte("\x08\x08\x08\x08"),
	}
}
