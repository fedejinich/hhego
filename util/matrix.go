package util

import (
	"math/big"
)

func Affine(M [][]uint64, v []uint64, b []uint64, modulus uint64) []uint64 {
	vo := matMul(M, v, modulus)
	return vecAdd(vo, b, modulus)
}

func Square(vi []uint64, modulus uint64) []uint64 {
	rows := len(vi)

	vo := make([]uint64, rows)

	for row := 0; row < rows; row++ {
		temp := new(big.Int).Mul(
			new(big.Int).SetUint64(vi[row]),
			new(big.Int).SetUint64(vi[row]))
		vo[row] = temp.Mod(temp, new(big.Int).SetUint64(modulus)).Uint64()
	}

	return vo
}

func matMul(M [][]uint64, vi []uint64, modulus uint64) []uint64 {
	cols := len(vi)
	rows := len(M)
	mod := new(big.Int).SetUint64(modulus)

	vo := make([]uint64, rows)

	for row := 0; row < rows; row++ {
		temp := new(big.Int).Mul(
			new(big.Int).SetUint64(vi[0]),
			new(big.Int).SetUint64(M[row][0]))
		vo[row] = temp.Mod(temp, mod).Uint64()
		for col := 1; col < cols; col++ {
			temp = new(big.Int).Mul(
				new(big.Int).SetUint64(vi[col]),
				new(big.Int).SetUint64(M[row][col]))
			vo[row] = new(big.Int).Add(
				new(big.Int).SetUint64((vo)[row]),
				temp.Mod(temp, mod)).Uint64()
			vo[row] %= modulus
		}
	}

	return vo
}

func vecAdd(vi []uint64, b []uint64, modulus uint64) []uint64 {
	rows := len(vi)

	vo := make([]uint64, rows)

	for row := 0; row < rows; row++ {
		vo[row] = (vi[row] + b[row]) % modulus
	}

	return vo
}
