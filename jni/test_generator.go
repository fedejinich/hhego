package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	bfv2 "github.com/fedejinich/hhego/bfv"
	"github.com/fedejinich/hhego/pasta"
	"io/ioutil"

	"github.com/fedejinich/hhego/util"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// generates test files
func generateCases() {
	cases := []util.BasicCase{
		{
			TestName: "test_add",
			CaseType: util.Add,
			El1:      []uint64{43, 32},
			El2:      []uint64{12, 23},
		},
		{
			TestName: "test_sub",
			CaseType: util.Sub,
			El1:      []uint64{43, 32},
			El2:      []uint64{12, 23},
		},
		{
			TestName: "test_mul",
			CaseType: util.Mul,
			El1:      []uint64{43, 32},
			El2:      []uint64{12, 23},
		},
	}

	// todo(fedejinich) this can be replaced with BfvParams
	bfvParams, _ := bfv.NewParametersFromLiteral(bfv.PN15QP827pq)

	keygen := bfv.NewKeyGenerator(bfvParams)
	bfvSK, _ := keygen.GenKeyPairNew()

	encryptor := bfv.NewEncryptor(bfvParams, bfvSK)

	evk := rlwe.NewEvaluationKeySet()
	evk.RelinearizationKey = keygen.GenRelinearizationKeyNew(bfvSK)
	evaluator := bfv.NewEvaluator(bfvParams, evk)
	encoder := bfv.NewEncoder(bfvParams)

	// generate serialized cases
	serializedCases := make([]util.SerializedCase, len(cases))
	for i, c := range cases {
		pt1 := bfv.NewPlaintext(bfvParams, bfvParams.MaxLevel())
		pt2 := bfv.NewPlaintext(bfvParams, bfvParams.MaxLevel())

		encoder.Encode(c.El1, pt1)
		encoder.Encode(c.El1, pt2)

		ct1 := encryptor.EncryptNew(pt1)
		ct2 := encryptor.EncryptNew(pt2)

		expectedResult := util.ExecuteOp(evaluator, ct1, ct2, c.CaseType)

		serializedCases[i] = newCase(c.TestName, c.CaseType, ct1, ct2,
			expectedResult, bfvSK, evk.RelinearizationKey)
	}

	// write as .json
	fmt.Println(len(serializedCases))
	for _, c := range serializedCases {
		// Write to a file
		err := ioutil.WriteFile(testName(c.TestName), toJSON(c), 0644)
		if err != nil {
			panic("couldn't write to file")
		}
	}

	// Write to a file
	// err := ioutil.WriteFile("output.json", toJSON(serializedCases), 0644)
	// if err != nil {
	// 	panic("couldn't write to file")
	// }
}

type TranscipherSerializedCase struct {
	EncryptedMessage   []byte `json:"encryptedMessage"`
	PastaSK            []byte `json:"pastaSK"`
	ExpectedResult     []byte `json:"expectedResult"`
	RelinearizationKey []byte `json:"relinearizationKey"`
	BfvSK              []byte `json:"bfvSK"`
	Message            []byte `json:"message"`
}

func generateTranscipherCase() {
	pastaSK := []uint64{
		0x07a30, 0x0cfe2, 0x03bbb, 0x06ab7, 0x0de0b, 0x0c36c, 0x01c39, 0x019e0,
		0x0e09c, 0x04441, 0x0c560, 0x00fd4, 0x0c611, 0x0a3fd, 0x0d408, 0x01b17,
		0x0fa02, 0x054ea, 0x0afeb, 0x0193b, 0x0b6fa, 0x09e80, 0x0e253, 0x03f49,
		0x0c8a5, 0x0c6a4, 0x0badf, 0x0bcfc, 0x0ecbd, 0x06ccd, 0x04f10, 0x0f1d6,
		0x07da9, 0x079bd, 0x08e84, 0x0b774, 0x07435, 0x09206, 0x086d4, 0x070d4,
		0x04383, 0x05d65, 0x0b015, 0x058fe, 0x0f0d1, 0x0c700, 0x0dc40, 0x02cea,
		0x096db, 0x06c84, 0x008ef, 0x02abc, 0x03fdf, 0x0ddaf, 0x028c7, 0x0ded4,
		0x0bb88, 0x020cd, 0x075c3, 0x0caf7, 0x0a8ff, 0x0eadd, 0x01c02, 0x083b1,
		0x0a439, 0x0e2db, 0x09baa, 0x02c09, 0x0b5ba, 0x0c7f5, 0x0161c, 0x0e94d,
		0x0bf6f, 0x070f1, 0x0f574, 0x0784b, 0x08cdb, 0x08529, 0x027c9, 0x010bc,
		0x079ca, 0x01ff1, 0x0219a, 0x00130, 0x0ff77, 0x012fb, 0x03ca6, 0x0d27d,
		0x05747, 0x0fa91, 0x00766, 0x04f27, 0x00254, 0x06e8d, 0x0e071, 0x0804e,
		0x08b0e, 0x08e59, 0x04cd8, 0x0485f, 0x0bde0, 0x03082, 0x01225, 0x01b5f,
		0x0a83e, 0x0794a, 0x05104, 0x09c19, 0x0fdcf, 0x036fe, 0x01e41, 0x00038,
		0x086e8, 0x07046, 0x02c07, 0x04953, 0x07869, 0x0e9c1, 0x0af86, 0x0503a,
		0x00f31, 0x0535c, 0x0c2cb, 0x073b9, 0x028e3, 0x03c2b, 0x0cb90, 0x00c33,
		0x08fe7, 0x068d3, 0x09a8c, 0x008e0, 0x09fe8, 0x0f107, 0x038ec, 0x0b014,
		0x007eb, 0x06335, 0x0afcc, 0x0d55c, 0x0a816, 0x0fa07, 0x05864, 0x0dc8f,
		0x07720, 0x0deef, 0x095db, 0x07cbe, 0x0834e, 0x09adc, 0x0bab8, 0x0f8f7,
		0x0b21a, 0x0ca98, 0x01a6c, 0x07e4a, 0x04545, 0x078a7, 0x0ba53, 0x00040,
		0x09bc5, 0x0bc7a, 0x0401c, 0x00c30, 0x00000, 0x0318d, 0x02e95, 0x065ed,
		0x03749, 0x090b3, 0x01e23, 0x0be04, 0x0b612, 0x08c0c, 0x06ea3, 0x08489,
		0x0a52c, 0x0aded, 0x0fd13, 0x0bd31, 0x0c225, 0x032f5, 0x06aac, 0x0a504,
		0x0d07e, 0x0bb32, 0x08174, 0x0bd8b, 0x03454, 0x04075, 0x06803, 0x03df5,
		0x091a0, 0x0d481, 0x09f04, 0x05c54, 0x0d54f, 0x00344, 0x09ffc, 0x00262,
		0x01fbf, 0x0461c, 0x01985, 0x05896, 0x0fedf, 0x097ce, 0x0b38d, 0x0492f,
		0x03764, 0x041ad, 0x02849, 0x0f927, 0x09268, 0x0bafd, 0x05727, 0x033bc,
		0x03249, 0x08921, 0x022da, 0x0b2dc, 0x0e42d, 0x055fa, 0x0a654, 0x073f0,
		0x08df1, 0x08149, 0x00d1b, 0x0ac47, 0x0f304, 0x03634, 0x0168b, 0x00c59,
		0x09f7d, 0x0596c, 0x0d164, 0x0dc49, 0x038ff, 0x0a495, 0x07d5a, 0x02d4,
		0x06c6c, 0x0ea76, 0x09af5, 0x0bea6, 0x08eea, 0x0fbb6, 0x09e45, 0x0e9db,
		0x0d106, 0x0e7fd, 0x04ddf, 0x08bb8, 0x0a3a4, 0x03bcd, 0x036d9, 0x05acf,
	}
	bfvParams, _ := bfv.NewParametersFromLiteral(bfv.PN15QP827pq)

	bfvSk, _ := rlwe.NewKeyGenerator(bfvParams.Parameters).
		GenKeyPairNew()
	bfvSKBytes, _ := bfvSk.MarshalBinary()

	pastaParams := pasta.Params{
		SecretKeySize:  pasta.SecretKeySize,
		PlaintextSize:  pasta.PlaintextSize,
		CiphertextSize: pasta.CiphertextSize,
		Rounds:         pasta.Rounds,
	}
	mod := bfvParams.T()
	pastaCipher := pasta.NewPasta(pastaSK, mod, pastaParams)

	// encrypt message with PASTA
	message := []uint64{23, 25}
	encryptedMessage := pastaCipher.Encrypt(message)
	encryptedMessageLen := uint64(len(encryptedMessage))

	// generate relin key
	rlk := rlwe.NewKeyGenerator(bfvParams.Parameters).
		GenRelinearizationKeyNew(bfvSk)
	rlkBytes, _ := rlk.MarshalBinary()

	// new bfv cipher
	encryptor, _, _, encoder, bfv, _ := bfv2.NewBFVPasta(uint64(bfvParams.N()), pasta.DefaultSecLevel, encryptedMessageLen, 20, 10, mod, bfvSk, rlk)

	// BFV encrypt PASTA secret key
	pastaSKCt := bfv2.EncryptPastaSecretKey(pastaSK, encoder, encryptor, bfv.Params)
	pastaSKCtBytes, _ := pastaSKCt.MarshalBinary()

	encryptedMessageBytes := toBytes(encryptedMessage)

	tSerialized := TranscipherSerializedCase{
		EncryptedMessage:   encryptedMessageBytes,
		PastaSK:            pastaSKCtBytes,
		RelinearizationKey: rlkBytes,
		BfvSK:              bfvSKBytes,
		Message:            toBytes(message),
	}

	// todo(fedejinich) this is duplicated code
	// write as .json
	// Write to a file
	err := ioutil.WriteFile("test_transcipher.json", toJSON(tSerialized), 0644)
	if err != nil {
		panic("couldn't write to file")
	}
}

type EncryptDecryptCase struct {
	BFVSK []byte `json:"bfvSK"`
}

func generateEncryptDecryptCase() {
	bfvParams, _ := bfv.NewParametersFromLiteral(bfv.PN15QP827pq)
	kg := rlwe.NewKeyGenerator(bfvParams.Parameters)
	sk, _ := kg.GenKeyPairNew()
	skBytes, _ := sk.MarshalBinary()

	edCase := EncryptDecryptCase{
		BFVSK: skBytes,
	}

	// todo(fedejinich) this is duplicated code
	// write as .json
	// Write to a file
	err := ioutil.WriteFile("test_encrypt_decrypt.json", toJSON(edCase), 0644)
	if err != nil {
		panic("couldn't write to file")
	}
}

func toBytes(message []uint64) []byte {
	var buf bytes.Buffer

	for _, v := range message {
		if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
			// Handle error if needed
			fmt.Println("binary.Write failed:", err)
		}
	}

	return buf.Bytes()
}

func newCase(testName string, caseType int, el1 *rlwe.Ciphertext, el2 *rlwe.Ciphertext, expectedResult *rlwe.Ciphertext, key *rlwe.SecretKey, relinearizationKey *rlwe.RelinearizationKey) util.SerializedCase {
	e1, _ := el1.MarshalBinary()
	e2, _ := el2.MarshalBinary()
	eR, _ := expectedResult.MarshalBinary()

	sk, _ := key.MarshalBinary()
	rk, _ := relinearizationKey.MarshalBinary()

	return util.SerializedCase{
		TestName:           testName,
		Operation:          caseType,
		El1:                e1,
		El2:                e2,
		ExpectedResult:     eR,
		SecretKey:          sk,
		RelinearizationKey: rk,
	}
}

type SimpleHHE struct {
	Op1Pasta           []byte `json:"op1Pasta"`
	Op1Real            []byte `json:"op1Real"`
	Op2Pasta           []byte `json:"op2Pasta"`
	Op2Real            []byte `json:"op2Real"`
	PastaSK            []byte `json:"pastaSK"`
	RelinearizationKey []byte `json:"rk"`
	BfvSK              []byte `json:"bfvSK"`
}

func generateSimpleHHE() {
	pastaSK := []uint64{
		0x07a30, 0x0cfe2, 0x03bbb, 0x06ab7, 0x0de0b, 0x0c36c, 0x01c39, 0x019e0,
		0x0e09c, 0x04441, 0x0c560, 0x00fd4, 0x0c611, 0x0a3fd, 0x0d408, 0x01b17,
		0x0fa02, 0x054ea, 0x0afeb, 0x0193b, 0x0b6fa, 0x09e80, 0x0e253, 0x03f49,
		0x0c8a5, 0x0c6a4, 0x0badf, 0x0bcfc, 0x0ecbd, 0x06ccd, 0x04f10, 0x0f1d6,
		0x07da9, 0x079bd, 0x08e84, 0x0b774, 0x07435, 0x09206, 0x086d4, 0x070d4,
		0x04383, 0x05d65, 0x0b015, 0x058fe, 0x0f0d1, 0x0c700, 0x0dc40, 0x02cea,
		0x096db, 0x06c84, 0x008ef, 0x02abc, 0x03fdf, 0x0ddaf, 0x028c7, 0x0ded4,
		0x0bb88, 0x020cd, 0x075c3, 0x0caf7, 0x0a8ff, 0x0eadd, 0x01c02, 0x083b1,
		0x0a439, 0x0e2db, 0x09baa, 0x02c09, 0x0b5ba, 0x0c7f5, 0x0161c, 0x0e94d,
		0x0bf6f, 0x070f1, 0x0f574, 0x0784b, 0x08cdb, 0x08529, 0x027c9, 0x010bc,
		0x079ca, 0x01ff1, 0x0219a, 0x00130, 0x0ff77, 0x012fb, 0x03ca6, 0x0d27d,
		0x05747, 0x0fa91, 0x00766, 0x04f27, 0x00254, 0x06e8d, 0x0e071, 0x0804e,
		0x08b0e, 0x08e59, 0x04cd8, 0x0485f, 0x0bde0, 0x03082, 0x01225, 0x01b5f,
		0x0a83e, 0x0794a, 0x05104, 0x09c19, 0x0fdcf, 0x036fe, 0x01e41, 0x00038,
		0x086e8, 0x07046, 0x02c07, 0x04953, 0x07869, 0x0e9c1, 0x0af86, 0x0503a,
		0x00f31, 0x0535c, 0x0c2cb, 0x073b9, 0x028e3, 0x03c2b, 0x0cb90, 0x00c33,
		0x08fe7, 0x068d3, 0x09a8c, 0x008e0, 0x09fe8, 0x0f107, 0x038ec, 0x0b014,
		0x007eb, 0x06335, 0x0afcc, 0x0d55c, 0x0a816, 0x0fa07, 0x05864, 0x0dc8f,
		0x07720, 0x0deef, 0x095db, 0x07cbe, 0x0834e, 0x09adc, 0x0bab8, 0x0f8f7,
		0x0b21a, 0x0ca98, 0x01a6c, 0x07e4a, 0x04545, 0x078a7, 0x0ba53, 0x00040,
		0x09bc5, 0x0bc7a, 0x0401c, 0x00c30, 0x00000, 0x0318d, 0x02e95, 0x065ed,
		0x03749, 0x090b3, 0x01e23, 0x0be04, 0x0b612, 0x08c0c, 0x06ea3, 0x08489,
		0x0a52c, 0x0aded, 0x0fd13, 0x0bd31, 0x0c225, 0x032f5, 0x06aac, 0x0a504,
		0x0d07e, 0x0bb32, 0x08174, 0x0bd8b, 0x03454, 0x04075, 0x06803, 0x03df5,
		0x091a0, 0x0d481, 0x09f04, 0x05c54, 0x0d54f, 0x00344, 0x09ffc, 0x00262,
		0x01fbf, 0x0461c, 0x01985, 0x05896, 0x0fedf, 0x097ce, 0x0b38d, 0x0492f,
		0x03764, 0x041ad, 0x02849, 0x0f927, 0x09268, 0x0bafd, 0x05727, 0x033bc,
		0x03249, 0x08921, 0x022da, 0x0b2dc, 0x0e42d, 0x055fa, 0x0a654, 0x073f0,
		0x08df1, 0x08149, 0x00d1b, 0x0ac47, 0x0f304, 0x03634, 0x0168b, 0x00c59,
		0x09f7d, 0x0596c, 0x0d164, 0x0dc49, 0x038ff, 0x0a495, 0x07d5a, 0x02d4,
		0x06c6c, 0x0ea76, 0x09af5, 0x0bea6, 0x08eea, 0x0fbb6, 0x09e45, 0x0e9db,
		0x0d106, 0x0e7fd, 0x04ddf, 0x08bb8, 0x0a3a4, 0x03bcd, 0x036d9, 0x05acf,
	}
	bfvParams, _ := bfv.NewParametersFromLiteral(bfv.PN15QP827pq)

	bfvSK, _ := rlwe.NewKeyGenerator(bfvParams.Parameters).
		GenKeyPairNew()
	bfvSKBytes, _ := bfvSK.MarshalBinary()

	pastaParams := pasta.Params{
		SecretKeySize:  pasta.SecretKeySize,
		PlaintextSize:  pasta.PlaintextSize,
		CiphertextSize: pasta.CiphertextSize,
		Rounds:         pasta.Rounds,
	}
	mod := bfvParams.T()
	pastaCipher := pasta.NewPasta(pastaSK, mod, pastaParams)

	// encrypt ops with pasta
	op1 := []uint64{1, 2}
	op1Pasta := pastaCipher.Encrypt(op1)
	op2 := []uint64{3, 4}
	op2Pasta := pastaCipher.Encrypt(op2)

	// generate relin key
	rlk := rlwe.NewKeyGenerator(bfvParams.Parameters).
		GenRelinearizationKeyNew(bfvSK)

	// new bfv cipher
	encryptor, _, _, encoder, bfv, evks := bfv2.NewBFVPasta(uint64(bfvParams.N()),
		pasta.DefaultSecLevel, uint64(len(op1)), 20, 10, mod, bfvSK, rlk)

	// BFV encrypt PASTA secret key
	pastaSKCt := bfv2.EncryptPastaSecretKey(pastaSK, encoder, encryptor, bfv.Params)
	pastaSKCtBytes, _ := pastaSKCt.MarshalBinary()

	// relin key bytes
	rlkBytes, _ := evks.RelinearizationKey.MarshalBinary()

	simpleHHE := SimpleHHE{
		Op1Pasta:           toBytes(op1Pasta),
		Op1Real:            toBytes(op1),
		Op2Pasta:           toBytes(op2Pasta),
		Op2Real:            toBytes(op2),
		PastaSK:            pastaSKCtBytes,
		RelinearizationKey: rlkBytes,
		BfvSK:              bfvSKBytes,
	}

	fmt.Println("op1Pasta")
	fmt.Println(op1Pasta)
	fmt.Println(toBytes(op1Pasta))
	//
	fmt.Println("op2Pasta")
	fmt.Println(op2Pasta)
	fmt.Println(toBytes(op2Pasta))

	// todo(fedejinich) this is duplicated code
	// write as .json
	// Write to a file
	err := ioutil.WriteFile("test_simple_hhe.json", toJSON(simpleHHE), 0644)
	if err != nil {
		panic("couldn't write to file")
	}

	//err2 := ioutil.WriteFile("test_simple_hhe_evks.bin", evkBytes, 0644)
	//if err2 != nil {
	//	fmt.Println("Error writing to file:", err2)
	//	return
	//}
}

func toJSON(c interface{}) []byte {
	jsonData, err := json.Marshal(c)
	if err != nil {
		panic("wrong json produced")
	}
	return jsonData
}

func testName(name string) string {
	fmt.Println(name)
	return fmt.Sprintf("%s.json", name)
}

func main() {
	//generateCases()
	//generateTranscipherCase()
	//generateEncryptDecryptCase()
	generateSimpleHHE()
}
