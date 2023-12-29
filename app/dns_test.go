package main

import "testing"

func TestCompressedQuestionDecoding(t *testing.T) {
	data := []byte{
		0x01, byte('F'), 0x03, byte('I'), byte('S'), byte('I'), 0x04, byte('A'), byte('R'), byte('P'), byte('A'), 0x00, // F.ISI.ARPA
		0x00, 0x01, 0x00, 0x01, // QType and QClass.
		0x03, byte('F'), byte('O'), byte('O'),
		0xC0, 0x00, // FOO.F.ISI.ARPA
		0x00, 0x01, 0x00, 0x01, // QType and QClass.
		0xC0, 0x06, // ARPA
		0x00, 0x01, 0x00, 0x01, // QType and QClass.
		0x00, // root
	}

	response := DNSResponse{}
	response.DNSQuestions = NewDNSQuestions(data, 3)
}
