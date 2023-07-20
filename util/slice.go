package util

import "encoding/binary"

func EqualSlices(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func EqualSlices2(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func Rotate(slice []uint64, start, middle, end uint64) []uint64 {
	if middle < start || middle > end {
		panic("this shouldnt happen")
	}

	if middle == start {
		return slice[end:]
	}

	if middle == end {
		return slice[start:]
	}

	tmp := append([]uint64{}, slice[start:middle]...)
	copy(slice[start:], slice[middle:end])
	copy(slice[end-uint64(len(tmp)):], tmp)

	return slice
}

// BytesToUint64 Convert uint64 slice to byte slice
func BytesToUint64(byteSlice []byte) []uint64 {
	length := len(byteSlice) / 8
	uint64Slice := make([]uint64, length)

	for i := 0; i < length; i++ {
		start := i * 8
		end := start + 8
		chunk := byteSlice[start:end]

		uint64Value := binary.BigEndian.Uint64(chunk)
		uint64Slice[i] = uint64Value
	}

	return uint64Slice
}

// Uint64ToBytes Convert uint64 slice to byte slice
func Uint64ToBytes(uint64Slice []uint64) []byte {
	byteSlice := make([]byte, len(uint64Slice)*8) // Each uint64 takes 8 bytes
	for i, value := range uint64Slice {
		binary.LittleEndian.PutUint64(byteSlice[i*8:], value)
	}

	return byteSlice
}
