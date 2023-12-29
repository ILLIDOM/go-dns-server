package main

import (
	"encoding/binary"
)

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
	NullByte     = byte(0x00)
)

type DNSResponse struct {
	DNSHeader    *DNSHeader     // 12bytes
	DNSQuestions []*DNSQuestion // length of DNSQuestion.Name + 4 Bytes (Type and Class) for each question
	DNSAnswers   []*DNSAnswer   // length is variable due to the data field
}

// Encode returns the BigEndian encoded DNSReply as a byte array
func (r *DNSResponse) Encode() []byte {
	// TODO: improve by creating a fixed size buffer first
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
	ID      uint16 // 16bits -> A random ID assigned to query packets. Response packets must reply with the same ID.
	Flags   Flags  // 16bits -> Flags
	QDCOUNT uint16 // 16bit -> Number of questions in the Question section.
	ANCOUNT uint16 // 16bit -> Number of records in the Answer section.
	NSCOUNT uint16 // 16bit -> Number of records in the Authority section.
	ARCOUNT uint16 // 16bit -> Number of records in the Additional section.
}

type Flags struct {
	// Flags contains the 16bit long DNS header flags
	QR     uint16 // 1bit -> 1 for a reply packet, 0 for a question packet.
	OPCODE uint16 // 4bit -> Specifies the kind of query in a message.
	AA     uint16 // 1bit -> 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
	TC     uint16 // 1bit -> 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
	RD     uint16 // 1bit -> Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
	RA     uint16 // 1bit -> Server sets this to 1 to indicate that recursion is available.
	Z      uint16 // 3bit -> Used by DNSSEC queries. At inception, it was reserved for future use.
	RCODE  uint16 // 4bit -> Response code indicating the status of the response.
}

func (f *Flags) Encode() uint16 {
	flags := uint16(0)
	flags |= f.QR << 15
	flags |= f.OPCODE << 11
	flags |= f.AA << 10
	flags |= f.TC << 9
	flags |= f.RD << 8
	flags |= f.RA << 7
	flags |= f.Z << 4
	flags |= f.RCODE
	return flags
}

func DecodeFlags(input uint16) Flags {
	// flags example binary: 00000001 00100000
	f := Flags{}
	f.QR = input >> 15 // get the MSB
	// OPCODE is obtained by shifting the flags 11 bits to the right and then masking with 0b01111 to get the last four bits
	f.OPCODE = (input >> 11) & 0b1111
	f.AA = (input >> 10) & 0b1
	f.TC = (input >> 9) & 0b1
	// RD value is extracted by shifting the flags 8 bits to the right and masking with 0b00000001
	f.RD = (input >> 8) & 0b1
	f.RA = (input >> 7) & 0b1
	f.Z = (input >> 4) & 0b1
	f.RCODE = input & 0b1
	return f
}

// Encode returns a 12byte long encoded DNS header
func (h *DNSHeader) Encode() []byte {
	buffer := make([]byte, 12)
	// write header into buffer
	binary.BigEndian.PutUint16(buffer[0:2], h.ID)
	binary.BigEndian.PutUint16(buffer[2:4], h.Flags.Encode())
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

func NewResponseFlags(flagBits uint16) Flags {
	receivedFlags := DecodeFlags(flagBits)
	responseFlags := Flags{
		QR:     1, // QR is always 1 for a DNS reply
		OPCODE: receivedFlags.OPCODE,
		AA:     0,
		TC:     0,
		RD:     receivedFlags.RD,
		RA:     0,
		Z:      0,
		RCODE:  0,
	}

	// if the OPCODE is not 0 (indicating a non-standard query), the RCODE is set to 4, which means "Not Implemented".
	if receivedFlags.OPCODE != 0 {
		responseFlags.RCODE = 4
	}

	return responseFlags
}

// NewDNSHeader creates a DNS header based on the received header inside the DNS request
func NewDNSHeader(receivedHeader []byte) *DNSHeader {
	header := &DNSHeader{}
	header.ID = binary.BigEndian.Uint16(receivedHeader[0:2])
	header.Flags = NewResponseFlags(binary.BigEndian.Uint16(receivedHeader[2:4]))
	header.QDCOUNT = binary.BigEndian.Uint16(receivedHeader[4:6])
	header.ANCOUNT = binary.BigEndian.Uint16(receivedHeader[6:8])
	header.NSCOUNT = binary.BigEndian.Uint16(receivedHeader[8:10])
	header.ARCOUNT = binary.BigEndian.Uint16(receivedHeader[10:12])
	return header
}

func extractName(body []byte, offset *int) []byte {
	var name []byte

	for {
		if body[*offset] == NullByte {
			name = append(name, body[*offset])
			*offset += 1
			break
		}

		if isCompressed(body[*offset]) {
			pointerOffset := int(binary.BigEndian.Uint16([]byte{body[*offset] & 0x3f, body[*offset+1]}))
			// decrease pointer offset by the header length because body does not contain the header
			pointerOffset -= 12
			name = append(name, extractName(body, &pointerOffset)...)
			// skip the two pointer bytes
			*offset += 2
			break
		}

		// first byte indicates the lenght of the following label
		length := int(body[*offset])
		// append the length to the name slice
		name = append(name, body[*offset])
		// proceed to the first data byte
		*offset++
		// extract the label
		label := body[*offset : *offset+length]
		// append the label to the name slice
		name = append(name, label...)
		// proceed to the next length or NullByte
		*offset += length
	}

	return name
}

func isCompressed(b byte) bool {
	// shift bits 6 times to the right and check if the two bits are set to 1 (11 = 3)
	return (b >> 6) == 3
}

func NewDNSQuestions(body []byte, numberOfQuestions uint16) []*DNSQuestion {
	questions := []*DNSQuestion{}
	offset := 0 // offset is 0 because the body does not contain the 12 header bytes
	// extract the names from the body
	for i := 0; i < int(numberOfQuestions); i++ {
		name := extractName(body, &offset)

		dnsType := binary.BigEndian.Uint16(body[offset : offset+2])
		dnsClass := binary.BigEndian.Uint16(body[offset+2 : offset+4])

		offset += 4

		q := &DNSQuestion{
			Name:  name,
			Type:  dnsType,
			Class: dnsClass,
		}

		questions = append(questions, q)
	}

	return questions
}

func NewDNSAnswers(questions []*DNSQuestion) []*DNSAnswer {
	answers := []*DNSAnswer{}

	for _, q := range questions {
		a := &DNSAnswer{
			Name:     q.Name,
			Type:     q.Type,
			Class:    q.Class,
			TTL:      60,
			RDLENGTH: 4,                          // only A records which have a length of 4
			RDATA:    []byte("\x08\x08\x08\x08"), // static IP but should be looked up inside the DNS zone file
		}
		answers = append(answers, a)
	}

	return answers
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
