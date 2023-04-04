package util

import (
	"math/big"
)

type Vector []uint64
type Matrix []Vector

func Affine(vo *Vector, M Matrix, vi Vector, b Vector, modulus uint64) {
	matMul(vo, M, vi, modulus)
	vecAdd(vo, *vo, b, modulus)
}

func Square(vo *Vector, vi Vector, modulus uint64) {
	rows := len(vi)

	if len(*vo) != rows {
		*vo = make(Vector, rows)
	}

	for row := 0; row < rows; row++ {
		temp := new(big.Int).Mul(new(big.Int).SetUint64(vi[row]), new(big.Int).SetUint64(vi[row]))
		(*vo)[row] = temp.Mod(temp, new(big.Int).SetUint64(modulus)).Uint64()
	}
}

func matMul(vo *Vector, M Matrix, vi Vector, modulus uint64) {
	cols := len(vi)
	rows := len(M)

	if len(*vo) != rows {
		*vo = make(Vector, rows)
	}

	for row := 0; row < rows; row++ {
		temp := new(big.Int).Mul(new(big.Int).SetUint64(vi[0]), new(big.Int).SetUint64(M[row][0]))
		(*vo)[row] = temp.Mod(temp, new(big.Int).SetUint64(modulus)).Uint64()
		for col := 1; col < cols; col++ {
			temp = new(big.Int).Mul(new(big.Int).SetUint64(vi[col]), new(big.Int).SetUint64(M[row][col]))
			(*vo)[row] = new(big.Int).Add(new(big.Int).SetUint64((*vo)[row]), temp.Mod(temp, new(big.Int).SetUint64(modulus))).Uint64()
			(*vo)[row] %= modulus
		}
	}
}

func vecAdd(vo *Vector, vi Vector, b Vector, modulus uint64) {
	rows := len(vi)

	if len(*vo) != rows {
		*vo = make(Vector, rows)
	}

	for row := 0; row < rows; row++ {
		(*vo)[row] = (vi[row] + b[row]) % modulus
	}
}
