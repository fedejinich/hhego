package util

import "fmt"

func Rotate(first, middle, last uint64, arr []uint64) uint64 {
	if first == middle {
		return last
	}
	if middle == last {
		return first
	}

	arrLen := len(arr)
	if first < 0 || middle < 0 || last < 0 || first >= uint64(arrLen) || middle >= uint64(arrLen) || last > uint64(arrLen) {
		fmt.Errorf("Invalid indices provided")
		return 87878 // Invalid indices provided
	}

	reverse(arr, first, middle)
	reverse(arr, middle, last)
	reverse(arr, first, last)
	return first + (last - middle)
}

func reverse(arr []uint64, start, end uint64) {
	for i, j := start, end-1; i < j; i, j = i+1, j-1 {
		arr[i], arr[j] = arr[j], arr[i]
	}
}

//func main() {
//	v := []int{2, 4, 2, 0, 5, 10, 7, 3, 7, 1}
//	fmt.Println("before sort:\t\t", v)
//
//	// insertion sort
//	for i := 1; i < len(v); i++ {
//		j := i
//		for j > 0 && v[j-1] > v[j] {
//			v[j], v[j-1] = v[j-1], v[j]
//			j--
//		}
//	}
//	fmt.Println("after sort:\t\t", v)
//
//	// simple rotation to the left
//	rotate(0, 1, len(v), v)
//	fmt.Println("simple rotate left:\t", v)
//
//	// simple rotation to the right
//	rotate(0, len(v)-1, len(v), v)
//	fmt.Println("simple rotate right:\t", v)
//}
