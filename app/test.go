package main

import (
	"encoding/binary"
	"fmt"
)

func test() {
	buf := []byte("hallo")
	var name uint16
	name = 1
	buf = binary.BigEndian.AppendUint16(buf, name)
	fmt.Printf(string(buf))
}
