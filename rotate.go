package util

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
