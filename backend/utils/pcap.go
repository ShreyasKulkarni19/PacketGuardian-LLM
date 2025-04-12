package utils

import (
	"encoding/binary"
	"os"
)

// Common PCAP magic numbers
var pcapMagicNumbers = []uint32{
	0xa1b2c3d4, // Standard PCAP
	0xa1b23c4d, // PCAP-NG
	0xd4c3b2a1, // Byte-swapped PCAP
}

func IsValidPCAP(filepath string) bool {
	file, err := os.Open(filepath)
	if err != nil {
		return false
	}
	defer file.Close()

	// Read first 4 bytes for magic number
	var magic uint32
	err = binary.Read(file, binary.BigEndian, &magic)
	if err != nil {
		return false
	}

	// Check against known PCAP magic numbers
	for _, validMagic := range pcapMagicNumbers {
		if magic == validMagic {
			return true
		}
	}
	return false
}
