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
	"fmt"
	bfv2 "github.com/fedejinich/hhego/bfv"
	"github.com/fedejinich/hhego/pasta"
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

	relinearizationKeyBytes := jBytesToBytes(env, jRelinearizationKey, jRelinearizationKeyLen)

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

	dataBytes := jBytesToBytes(env, jData, jDataLen)
	skBytes := jBytesToBytes(env, jSK, jSKLen)

	data := bfv.NewCiphertext(BfvParams, 1, BfvParams.MaxLevel())
	data.UnmarshalBinary(dataBytes)

	sk := rlwe.NewSecretKey(BfvParams.Parameters)
	sk.UnmarshalBinary(skBytes)

	// todo(fedejinich) replace this with generic encryptor decryptor
	bfvCipher := bfv2.NewCipherPastaWithSKAndRK(uint64(BfvParams.N()), pasta.DefaultSecLevel, 0,
		20, 10, true, BfvParams.T(), sk, nil)
	res := bfvCipher.DecryptPacked(data, uint64(dataSize)) // todo(fedejinich) this is hardcoded

	// output
	resBytes := uint64ArrayToBytes(res)
	var cOutput *C.char = C.CString(string(resBytes)) // todo(fedejinich) will string always work as expected?
	defer C.free(unsafe.Pointer(cOutput))
	r := C.fromCByteArray(env, cOutput, C.int(len(resBytes)))

	return r
}

//export Java_org_rsksmart_BFV_encrypt
func Java_org_rsksmart_BFV_encrypt(env *C.JNIEnv, obj C.jobject, jData C.jbyteArray, jDataLen C.jint,
	jSK C.jbyteArray, jSKLen C.jint) C.jbyteArray {

	dataBytes := jBytesToBytes(env, jData, jDataLen)
	skBytes := jBytesToBytes(env, jSK, jSKLen)

	data := bytesToUint64Array(dataBytes)

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

func uint64ArrayToBytes(message []uint64) []byte {
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

	// deserialize keys
	pastaSkBytes := jBytesToBytes(env, jPastaSK, jPastaSKLen)
	pastaSK := bytesToCiphertext(pastaSkBytes)

	bfvSKBytes := jBytesToBytes(env, jBfvSK, jBfvSKLen)
	bfvSK := bytesToSecretKey(bfvSKBytes, BfvParams.Parameters)

	rkBytes := jBytesToBytes(env, jRelinKey, jRelinKeyLen)
	rk := bytesToRelinKey(rkBytes, BfvParams.Parameters)

	// deserialize message
	messageByteArray := jBytesToBytes(env, jEncryptedMessageBytes, jEncryptedMessageLen)
	message := bytesToUint64Array(messageByteArray)

	bfvCipher := bfv2.NewCipherPastaWithSKAndRK(uint64(BfvParams.N()), pasta.DefaultSecLevel, uint64(len(message)), 20, 10, true, BfvParams.T(), bfvSK, rk)

	// transcipher
	pastaParams := pasta.Params{
		SecretKeySize:  pasta.SecretKeySize,
		PlaintextSize:  pasta.PlaintextSize,
		CiphertextSize: pasta.CiphertextSize,
		Rounds:         pasta.Rounds,
	}
	res := bfvCipher.Transcipher(message, pastaSK, pastaParams, pasta.DefaultSecLevel)

	// output
	resBytes, _ := res.MarshalBinary()
	var cOutput *C.char = C.CString(string(resBytes)) // todo(fedejinich) will string always work as expected?
	defer C.free(unsafe.Pointer(cOutput))
	r := C.fromCByteArray(env, cOutput, C.int(len(resBytes)))

	return r
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

func internalExecute(env *C.JNIEnv, jOp0 C.jbyteArray, jOp0Len C.jint,
	jOp1 C.jbyteArray, jOp1Len C.jint, evaluator bfv.Evaluator, opType int) C.jbyteArray {

	// bytesToUint64Array
	op0Bytes := jBytesToBytes(env, jOp0, jOp0Len)
	op1Bytes := jBytesToBytes(env, jOp1, jOp1Len)

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

func jBytesToBytes(env *C.JNIEnv, jOp0 C.jbyteArray, jOp0Len C.jint) []byte {
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

func bytesToUint64Array(data []byte) []uint64 {
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
