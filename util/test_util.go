package util

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

const (
	Add int = iota
	Sub
	Mul
)

type BasicCase struct {
	TestName string
	CaseType int
	El1      []uint64
	El2      []uint64
}

type SerializedCase struct {
	TestName           string `json:"testName"`
	Operation          int    `json:"operation"`
	El1                []byte `json:"el1"`
	El2                []byte `json:"el2"`
	ExpectedResult     []byte `json:"expectedResult"`
	SecretKey          []byte `json:"secretKey"`
	RelinearizationKey []byte `json:"relinearizationKey"`
}

func ExecuteOp(evaluator bfv.Evaluator, ct1 *rlwe.Ciphertext, ct2 *rlwe.Ciphertext, caseType int) *rlwe.Ciphertext {
	var result *rlwe.Ciphertext
	switch caseType {
	case Add:
		fmt.Println("ExecuteOpAdd")
		result = evaluator.AddNew(ct1, ct2)
		break
	case Sub:
		fmt.Println("ExecuteOpSub")
		result = evaluator.SubNew(ct1, ct2)
		break
	case Mul:
		{
			fmt.Println("ExecuteOpMul")
			result = evaluator.MulRelinNew(ct1, ct2)
			break
		}
	default:
		panic("this is unexpected")
	}

	return result
}

func NoiseBudget(evaluator bfv.Evaluator, decryptor rlwe.Decryptor, encoder bfv.Encoder, ct *rlwe.Ciphertext, pt *rlwe.Plaintext) int {
	vec := evaluator.SubNew(ct, pt)
	res, _, _ := rlwe.Norm(vec, decryptor)

	// resCt0, _, _ := rlwe.Norm(ct0, decryptor)
	// resCt1, _, _ := rlwe.Norm(ct1, decryptor)
	fmt.Printf("STD(noise)res: %d\n", int(res))
	// fmt.Printf("STD(noise)ct0: %d\n", int(resCt0))
	// fmt.Printf("STD(noise)ct1: %d\n", int(resCt1))
	//
	// ct3 := evaluator.MulRelinNew(ct0, ct0)
	// resCt3, _, _ := rlwe.Norm(ct3, decryptor)
	// fmt.Printf("STD(noise)ct3: %d\n", int(resCt3))
	//
	// ct4 := evaluator.MulRelinNew(ct3, ct3)
	// resCt4, _, _ := rlwe.Norm(ct4, decryptor)
	// fmt.Printf("STD(noise)ct4: %d\n", int(resCt4))
	//
	// ct5 := evaluator.MulRelinNew(ct4, ct4)
	// resCt5, _, _ := rlwe.Norm(ct5, decryptor)
	// fmt.Printf("STD(noise)ct5: %d\n", int(resCt5))
	//
	// evaluator.MulRelin(ct5, ct5, ct5)
	// resCt6, _, _ := rlwe.Norm(ct5, decryptor)
	// fmt.Printf("STD(noise)ct6: %d\n", int(resCt6))
	//
	// evaluator.MulRelin(ct5, ct5, ct5)
	// resCt7, _, _ := rlwe.Norm(ct5, decryptor)
	// fmt.Printf("STD(noise)ct7: %d\n", int(resCt7))

	return int(res)
}
