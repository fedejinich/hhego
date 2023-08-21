package util

import "C"
import (
	"bytes"
	"encoding/binary"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func Uint64ArrayToBytes(message []uint64) []byte {
	var buf bytes.Buffer

	for _, v := range message {
		if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
			panic("cannot convert uint64[] to []byte") // todo(fedejinich) panic?
		}
	}

	return buf.Bytes()
}

func BytesToRelinKey(rkBytes []byte, params rlwe.Parameters) *rlwe.RelinearizationKey {
	rk := rlwe.NewRelinearizationKey(params)
	rk.UnmarshalBinary(rkBytes)

	return rk
}

func BytesToSecretKey(skBytes []byte, params rlwe.Parameters) *rlwe.SecretKey {
	sk := rlwe.NewSecretKey(params)
	sk.UnmarshalBinary(skBytes)

	return sk
}

func BytesToCiphertext(bytes []byte, bfvParams bfv.Parameters) *rlwe.Ciphertext {
	ct := bfv.NewCiphertext(bfvParams, 1, bfvParams.MaxLevel())
	ct.UnmarshalBinary(bytes)

	return ct
}

func BytesToUint64Array(data []byte) []uint64 {
	var uint64s []uint64

	buffer := bytes.NewBuffer(data)
	for buffer.Len() > 0 {
		var value uint64
		if err := binary.Read(buffer, binary.LittleEndian, &value); err != nil {
			panic("cannot convert []byte to []uint64 ") // todo(fedejinich) panic?
		}
		uint64s = append(uint64s, value)
	}

	return uint64s
}
