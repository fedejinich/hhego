package main

// #include <jni.h>
// #include <stdlib.h>
// static jbyte* getCByteArray(JNIEnv *env, jbyteArray input) {
//     return (*env)->GetByteArrayElements(env, input, NULL);
// }
// static void releaseCByteArray(JNIEnv *env, jbyteArray input, jbyte* cData) {
//     (*env)->ReleaseByteArrayElements(env, input, cData, 0);
// }
// static jbyteArray fromCByteArray(JNIEnv *env, char *input, jint len) {
//     jbyteArray result=(*env)->NewByteArray(env, len);
//	   (*env)->SetByteArrayRegion(env, result, 0, len, input);
//	   return result;
// }
import "C"
import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	bfv2 "github.com/fedejinich/hhego/bfv"
	"github.com/fedejinich/hhego/pasta"
	"io/ioutil"
	"log"
	"unsafe"

	"github.com/fedejinich/hhego/util"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func main() {
}

var ParamsLiteral = bfv.PN15QP827pq // todo(fedejinich) should we parametrize this
var BfvParams, _ = bfv.NewParametersFromLiteral(ParamsLiteral)

//export Java_org_rsksmart_BFV_add
func Java_org_rsksmart_BFV_add(env *C.JNIEnv, obj C.jobject, jOp0 C.jbyteArray, jOp0Len C.jint,
	jOp1 C.jbyteArray, jOp1Len C.jint) C.jbyteArray {

	r := internalExecute(env, jOp0, jOp0Len, jOp1, jOp1Len, evaluatorBy(BfvParams, nil), util.Add)

	return r
}

//export Java_org_rsksmart_BFV_sub
func Java_org_rsksmart_BFV_sub(env *C.JNIEnv, obj C.jobject, jOp0 C.jbyteArray, jOp0Len C.jint,
	jOp1 C.jbyteArray, jOp1Len C.jint) C.jbyteArray {

	r := internalExecute(env, jOp0, jOp0Len, jOp1, jOp1Len, evaluatorBy(BfvParams, nil), util.Sub)

	return r
}

//export Java_org_rsksmart_BFV_mul
func Java_org_rsksmart_BFV_mul(env *C.JNIEnv, obj C.jobject, jOp0 C.jbyteArray, jOp0Len C.jint,
	jOp1 C.jbyteArray, jOp1Len C.jint, jRelinearizationKey C.jbyteArray, jRelinearizationKeyLen C.jint) C.jbyteArray {

	relinearizationKeyBytes := deserializeJByteArray(env, jRelinearizationKey, jRelinearizationKeyLen)

	// create evaluator with relinearization keys
	rk := rlwe.NewRelinearizationKey(BfvParams.Parameters)
	rk.UnmarshalBinary(relinearizationKeyBytes)
	evaluator := evaluatorBy(BfvParams, rk)

	r := internalExecute(env, jOp0, jOp0Len, jOp1, jOp1Len, evaluator, util.Mul)

	return r
}

//export Java_org_rsksmart_BFV_decrypt
func Java_org_rsksmart_BFV_decrypt(env *C.JNIEnv, obj C.jobject, jData C.jbyteArray, jDataLen C.jint,
	dataSize C.jint, jSK C.jbyteArray, jSKLen C.jint) C.jbyteArray {

	dataBytes := deserializeJByteArray(env, jData, jDataLen)
	skBytes := deserializeJByteArray(env, jSK, jSKLen)

	data := bfv.NewCiphertext(BfvParams, 1, BfvParams.MaxLevel())
	data.UnmarshalBinary(dataBytes)

	sk := rlwe.NewSecretKey(BfvParams.Parameters)
	sk.UnmarshalBinary(skBytes)

	// todo(fedejinich) replace this with generic encryptor decryptor
	bfvCipher := bfv2.NewCipherPastaWithSKAndRK(uint64(BfvParams.N()), pasta.DefaultSecLevel, 0,
		20, 10, true, BfvParams.T(), sk, nil)
	res := bfvCipher.DecryptPacked(data, uint64(dataSize)) // todo(fedejinich) this is hardcoded

	// output
	resBytes := toBytes2(res)
	var cOutput *C.char = C.CString(string(resBytes)) // todo(fedejinich) will string always work as expected?
	defer C.free(unsafe.Pointer(cOutput))
	r := C.fromCByteArray(env, cOutput, C.int(len(resBytes)))

	return r
}

//export Java_org_rsksmart_BFV_encrypt
func Java_org_rsksmart_BFV_encrypt(env *C.JNIEnv, obj C.jobject, jData C.jbyteArray, jDataLen C.jint,
	jSK C.jbyteArray, jSKLen C.jint) C.jbyteArray {

	dataBytes := deserializeJByteArray(env, jData, jDataLen)
	skBytes := deserializeJByteArray(env, jSK, jSKLen)

	data := toUint64Array(dataBytes)

	fmt.Println("this data")
	fmt.Println(data)

	sk := rlwe.NewSecretKey(BfvParams.Parameters)
	sk.UnmarshalBinary(skBytes)

	encoder := bfv.NewEncoder(BfvParams)
	dataPt := bfv.NewPlaintext(BfvParams, BfvParams.MaxLevel())
	encoder.Encode(data, dataPt)

	encryptor := bfv.NewEncryptor(BfvParams, sk)
	dataCt := encryptor.EncryptNew(dataPt)

	// output
	resBytes, _ := dataCt.MarshalBinary()
	var cOutput *C.char = C.CString(string(resBytes)) // todo(fedejinich) will string always work as expected?
	defer C.free(unsafe.Pointer(cOutput))
	r := C.fromCByteArray(env, cOutput, C.int(len(resBytes)))

	return r
}

func toBytes2(message []uint64) []byte {
	var buf bytes.Buffer

	for _, v := range message {
		if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
			// Handle error if needed
			fmt.Println("binary.Write failed:", err)
		}
	}

	return buf.Bytes()
}

//export Java_org_rsksmart_BFV_transcipher
func Java_org_rsksmart_BFV_transcipher(env *C.JNIEnv, obj C.jobject, jEncryptedMessageBytes C.jbyteArray,
	jEncryptedMessageLen C.jint, jPastaSK C.jbyteArray, jPastaSKLen C.jint, jRelinKey C.jbyteArray,
	jRelinKeyLen C.jint, jBfvSK C.jbyteArray, jBfvSKLen C.jint) C.jbyteArray {

	messageByteArray := deserializeJByteArray(env, jEncryptedMessageBytes, jEncryptedMessageLen)
	message := toUint64Array(messageByteArray)
	pastaSkBytes := deserializeJByteArray(env, jPastaSK, jPastaSKLen)
	relinKeyBytes := deserializeJByteArray(env, jRelinKey, jRelinKeyLen)
	bfvSKBytes := deserializeJByteArray(env, jBfvSK, jBfvSKLen)

	pastaSK := bytesToCiphertext(pastaSkBytes)
	bfvSK := bytesToSecretKey(bfvSKBytes, BfvParams.Parameters)
	rk := bytesToRelinKey(relinKeyBytes, BfvParams.Parameters)

	bfvCipher := bfv2.NewCipherPastaWithSKAndRK(uint64(BfvParams.N()), pasta.DefaultSecLevel, uint64(len(message)), 20, 10, true, BfvParams.T(), bfvSK, rk)

	pastaParams := pasta.Params{
		SecretKeySize:  pasta.SecretKeySize,
		PlaintextSize:  pasta.PlaintextSize,
		CiphertextSize: pasta.CiphertextSize,
		Rounds:         pasta.Rounds,
	}

	mod := bfvCipher.Params.T()

	p := pasta.NewPasta(psk(), mod, pastaParams)
	d2 := p.Decrypt(message)
	fmt.Println("hack decrypt")
	fmt.Println(d2)

	if !pastaSK.Equal(readPSK(BfvParams)) {
		panic("different sks!")
	}

	res := bfvCipher.Transcipher(message, pastaSK, pastaParams, pasta.DefaultSecLevel)

	decrypted := bfvCipher.DecryptPacked(&res, uint64(len(d2)))
	if !util.EqualSlices(decrypted, d2) {
		fmt.Println(decrypted)
		panic("should be equal slices")
	}

	// output
	resBytes, _ := res.MarshalBinary()
	var cOutput *C.char = C.CString(string(resBytes)) // todo(fedejinich) will string always work as expected?
	defer C.free(unsafe.Pointer(cOutput))
	r := C.fromCByteArray(env, cOutput, C.int(len(resBytes)))

	return r
}

type TAux struct {
	EncryptedMessage   []byte `json:"encryptedMessage"`
	PastaSK            []byte `json:"pastaSK"`
	ExpectedResult     []byte `json:"expectedResult"`
	RelinearizationKey []byte `json:"relinearizationKey"`
	BfvSK              []byte `json:"bfvSK"`
	Message            []byte `json:"message"`
}

func readPSK(params bfv.Parameters) *rlwe.Ciphertext {
	fileContent, err := ioutil.ReadFile("/Users/fedejinich/Projects/hhejava/src/test/resources/test_transcipher.json")
	if err != nil {
		log.Fatalf("Failed reading file: %s", err)
	}

	var t TAux

	// Unmarshal the file content into the 'users' slice
	err = json.Unmarshal(fileContent, &t)
	if err != nil {
		log.Fatalf("Error unmarshaling: %s", err)
	}

	pskBytes := t.PastaSK
	psk := bfv.NewCiphertext(params, 1, BfvParams.MaxLevel())
	psk.UnmarshalBinary(pskBytes)

	return psk
}

func bytesToRelinKey(rkBytes []byte, params rlwe.Parameters) *rlwe.RelinearizationKey {
	rk := rlwe.NewRelinearizationKey(params)
	rk.UnmarshalBinary(rkBytes)

	return rk
}

func bytesToSecretKey(skBytes []byte, params rlwe.Parameters) *rlwe.SecretKey {
	sk := rlwe.NewSecretKey(params)
	sk.UnmarshalBinary(skBytes)

	return sk
}

func psk() []uint64 {
	return []uint64{
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
}

func internalExecute(env *C.JNIEnv, jOp0 C.jbyteArray, jOp0Len C.jint,
	jOp1 C.jbyteArray, jOp1Len C.jint, evaluator bfv.Evaluator, opType int) C.jbyteArray {

	// toUint64Array
	op0Bytes := deserializeJByteArray(env, jOp0, jOp0Len)
	op1Bytes := deserializeJByteArray(env, jOp1, jOp1Len)

	// execute
	res := util.ExecuteOp(evaluator, bytesToCiphertext(op0Bytes), bytesToCiphertext(op1Bytes), opType)

	// output
	resBytes, _ := res.MarshalBinary()
	var cOutput *C.char = C.CString(string(resBytes)) // todo(fedejinich) will string always work as expected?
	defer C.free(unsafe.Pointer(cOutput))
	r := C.fromCByteArray(env, cOutput, C.int(len(resBytes)))

	return r
}

func bytesToCiphertext(bytes []byte) *rlwe.Ciphertext {
	ct := bfv.NewCiphertext(BfvParams, 1, BfvParams.MaxLevel())
	ct.UnmarshalBinary(bytes)

	return ct
}

func deserializeJByteArray(env *C.JNIEnv, jOp0 C.jbyteArray, jOp0Len C.jint) []byte {
	cOp0 := C.getCByteArray(env, jOp0)
	op0 := C.GoBytes(unsafe.Pointer(cOp0), jOp0Len)
	defer C.releaseCByteArray(env, jOp0, cOp0)
	return op0
}

func evaluatorBy(params bfv.Parameters, rKey *rlwe.RelinearizationKey) bfv.Evaluator {
	evk := rlwe.NewEvaluationKeySet()
	if rKey != nil {
		evk.RelinearizationKey = rKey
	}

	evaluator := bfv.NewEvaluator(params, evk)

	return evaluator
}

func toUint64Array(data []byte) []uint64 {
	var uint64s []uint64

	buffer := bytes.NewBuffer(data)
	for buffer.Len() > 0 {
		var value uint64
		if err := binary.Read(buffer, binary.LittleEndian, &value); err != nil {
			// Handle error if needed
			fmt.Println("binary.Read failed:", err)
		}
		uint64s = append(uint64s, value)
	}

	return uint64s
}
