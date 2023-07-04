package util

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
