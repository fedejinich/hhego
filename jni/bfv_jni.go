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

	evaluator := evaluatorWithRK(BfvParams, nil)
	r := executeOp(env, jOp0, jOp0Len, jOp1, jOp1Len, evaluator, util.Add, BfvParams)

	return r
}

//export Java_org_rsksmart_BFV_sub
func Java_org_rsksmart_BFV_sub(env *C.JNIEnv, obj C.jobject, jOp0 C.jbyteArray, jOp0Len C.jint,
	jOp1 C.jbyteArray, jOp1Len C.jint) C.jbyteArray {

	evaluator := evaluatorWithRK(BfvParams, nil)
	r := executeOp(env, jOp0, jOp0Len, jOp1, jOp1Len, evaluator, util.Sub, BfvParams)

	return r
}

//export Java_org_rsksmart_BFV_mul
func Java_org_rsksmart_BFV_mul(env *C.JNIEnv, obj C.jobject, jOp0 C.jbyteArray, jOp0Len C.jint,
	jOp1 C.jbyteArray, jOp1Len C.jint, jRelinearizationKey C.jbyteArray, jRelinearizationKeyLen C.jint) C.jbyteArray {

	relinearizationKeyBytes := jBytesToBytes(env, jRelinearizationKey, jRelinearizationKeyLen)

	// create evaluator with relinearization keys
	rk := rlwe.NewRelinearizationKey(BfvParams.Parameters)
	rk.UnmarshalBinary(relinearizationKeyBytes)
	evaluator := evaluatorWithRK(BfvParams, rk)

	r := executeOp(env, jOp0, jOp0Len, jOp1, jOp1Len, evaluator, util.Mul, BfvParams)

	return r
}

//export Java_org_rsksmart_BFV_decrypt
func Java_org_rsksmart_BFV_decrypt(env *C.JNIEnv, obj C.jobject, jData C.jbyteArray, jDataLen C.jint,
	jSK C.jbyteArray, jSKLen C.jint) C.jbyteArray {

	// deserialize keys
	skBytes := jBytesToBytes(env, jSK, jSKLen)
	sk := rlwe.NewSecretKey(BfvParams.Parameters)
	sk.UnmarshalBinary(skBytes)

	// deserialize data
	dataBytes := jBytesToBytes(env, jData, jDataLen)
	data := bfv.NewCiphertext(BfvParams, 1, BfvParams.MaxLevel())
	data.UnmarshalBinary(dataBytes)

	decryptor := bfv.NewDecryptor(BfvParams, sk)
	encoder := bfv.NewEncoder(BfvParams)

	decryptedPt := decryptor.DecryptNew(data)
	decrypted := encoder.DecodeUintNew(decryptedPt)

	// output
	d := util.Uint64ArrayToBytes(decrypted)
	jByteArray := buildJByteArray(env, d)

	return jByteArray
}

//export Java_org_rsksmart_BFV_encrypt
func Java_org_rsksmart_BFV_encrypt(env *C.JNIEnv, obj C.jobject, jData C.jbyteArray, jDataLen C.jint,
	jSK C.jbyteArray, jSKLen C.jint) C.jbyteArray {

	// deserialize data
	dataBytes := jBytesToBytes(env, jData, jDataLen)
	data := util.BytesToUint64Array(dataBytes)

	// deserialize keys
	skBytes := jBytesToBytes(env, jSK, jSKLen)
	sk := rlwe.NewSecretKey(BfvParams.Parameters)
	sk.UnmarshalBinary(skBytes)

	// encrypt
	encoder := bfv.NewEncoder(BfvParams)
	dataPt := bfv.NewPlaintext(BfvParams, BfvParams.MaxLevel())
	encoder.Encode(data, dataPt)

	encryptor := bfv.NewEncryptor(BfvParams, sk)
	dataCt := encryptor.EncryptNew(dataPt)

	// output
	resBytes, _ := dataCt.MarshalBinary()
	r := buildJByteArray(env, resBytes)

	return r
}

//export Java_org_rsksmart_BFV_transcipher
func Java_org_rsksmart_BFV_transcipher(env *C.JNIEnv, obj C.jobject, jEncryptedMessageBytes C.jbyteArray,
	jEncryptedMessageLen C.jint, jPastaSK C.jbyteArray, jPastaSKLen C.jint, jRelinKey C.jbyteArray,
	jRelinKeyLen C.jint, jBfvSK C.jbyteArray, jBfvSKLen C.jint) C.jbyteArray {

	// deserialize keys
	pastaSkBytes := jBytesToBytes(env, jPastaSK, jPastaSKLen)
	pastaSK := util.BytesToCiphertext(pastaSkBytes, BfvParams)

	bfvSKBytes := jBytesToBytes(env, jBfvSK, jBfvSKLen)
	bfvSK := util.BytesToSecretKey(bfvSKBytes, BfvParams.Parameters)

	rkBytes := jBytesToBytes(env, jRelinKey, jRelinKeyLen)
	rk := util.BytesToRelinKey(rkBytes, BfvParams.Parameters)

	// deserialize message
	messageByteArray := jBytesToBytes(env, jEncryptedMessageBytes, jEncryptedMessageLen)

	message := util.BytesToUint64Array(messageByteArray)

	_, _, evaluator, encoder, _, _ := bfv2.NewBFVPasta(uint64(BfvParams.N()), pasta.DefaultSecLevel,
		uint64(len(message)), 20, 10, BfvParams.T(), bfvSK, rk)

	// transcipher
	pastaParams := pasta.Params{
		SecretKeySize:  pasta.SecretKeySize,
		PlaintextSize:  pasta.PlaintextSize,
		CiphertextSize: pasta.CiphertextSize,
		Rounds:         pasta.Rounds,
	}
	res := bfv2.Transcipher(message, pastaSK, pastaParams, pasta.DefaultSecLevel, encoder, evaluator, BfvParams)

	// output
	resBytes, _ := res.MarshalBinary()
	var cOutput *C.char = C.CString(string(resBytes)) // todo(fedejinich) will string always work as expected?
	defer C.free(unsafe.Pointer(cOutput))
	r := C.fromCByteArray(env, cOutput, C.int(len(resBytes)))

	return r
}

//export Java_org_rsksmart_BFV_transcipher2
func Java_org_rsksmart_BFV_transcipher2(env *C.JNIEnv, obj C.jobject, jEncryptedMessageBytes C.jbyteArray,
	jEncryptedMessageLen C.jint, jPastaSK C.jbyteArray, jPastaSKLen C.jint, jEvks C.jbyteArray,
	jEvksLen C.jint) C.jbyteArray {

	// deserialize keys
	pastaSkBytes := jBytesToBytes(env, jPastaSK, jPastaSKLen)
	pastaSK := util.BytesToCiphertext(pastaSkBytes, BfvParams)

	//bfvSKBytes := jBytesToBytes(env, jBfvSK, jBfvSKLen)
	//bfvSK := util.BytesToSecretKey(bfvSKBytes, BfvParams.Parameters)
	//
	evksBytes := jBytesToBytes(env, jEvks, jEvksLen)
	evks := util.BytesToEvks(evksBytes)

	// deserialize message
	messageByteArray := jBytesToBytes(env, jEncryptedMessageBytes, jEncryptedMessageLen)
	message := util.BytesToUint64Array(messageByteArray)

	_, _, evaluator, encoder, _, _ := bfv2.NewBFVPastaEvks(uint64(BfvParams.N()), BfvParams.T(), *evks, nil)

	// transcipher
	pastaParams := pasta.Params{
		SecretKeySize:  pasta.SecretKeySize,
		PlaintextSize:  pasta.PlaintextSize,
		CiphertextSize: pasta.CiphertextSize,
		Rounds:         pasta.Rounds,
	}

	fmt.Println("transciphering message")
	fmt.Println(message)

	res := bfv2.Transcipher(message, pastaSK, pastaParams, pasta.DefaultSecLevel, encoder, evaluator, BfvParams)

	// output
	resBytes, _ := res.MarshalBinary()
	var cOutput *C.char = C.CString(string(resBytes)) // todo(fedejinich) will string always work as expected?
	defer C.free(unsafe.Pointer(cOutput))
	r := C.fromCByteArray(env, cOutput, C.int(len(resBytes)))

	return r
}

//export Java_org_rsksmart_BFV_noiseBudget
func Java_org_rsksmart_BFV_noiseBudget(env *C.JNIEnv, obj C.jobject, jCt0 C.jbyteArray, jCt0Len C.jint, jSk C.jbyteArray, jSkLen C.jint) C.jint {
	ct0Bytes := jBytesToBytes(env, jCt0, jCt0Len)
	ct0 := util.BytesToCiphertext(ct0Bytes, BfvParams)

	// deserialize secret key
	skBytes := jBytesToBytes(env, jSk, jSkLen)
	sk := rlwe.NewSecretKey(BfvParams.Parameters)
	sk.UnmarshalBinary(skBytes)

	decryptor := bfv.NewDecryptor(BfvParams, sk)
	evaluator := evaluatorWithRK(BfvParams, rlwe.NewRelinearizationKey(BfvParams.Parameters))
	encoder := bfv.NewEncoder(BfvParams)

	noiseBudget := bfv2.NoiseBudget(decryptor, encoder, evaluator, ct0)
	// pt := decryptor.DecryptNew(ct0)
	// values := encoder.DecodeUintNew(pt)
	// // noiseBudget := util.NoiseBudget(evaluator, decryptor, ct0, pt)
	// noiseBudget := PrintNoise(evaluator, decryptor, encoder, ct0, values)
	// noiseBudgetC := C.jint(noiseBudget)

	// return noiseBudgetC
	noiseBudgetInt := int(noiseBudget)

	fmt.Printf("int noise %d\n", noiseBudgetInt)

	return C.jint(noiseBudgetInt)
}

// PrintNoise prints the standard deviation of the noise in the given ciphertext.
func PrintNoise(evaluator bfv.Evaluator, decryptor rlwe.Decryptor, encoder bfv.Encoder, ct *rlwe.Ciphertext, values []uint64) int {
	// Encode the coefficients back to a plaintext
	pt := bfv.NewPlaintext(BfvParams, ct.Level())
	encoder.Encode(values, pt)

	// Subtract the encoded plaintext from the original ciphertext
	vec := evaluator.SubNew(ct, pt)

	// Calculate the norm of the resulting ciphertext, which gives the noise
	res, _, _ := rlwe.Norm(vec, decryptor)

	// Log the standard deviation of the noise
	fmt.Printf("STD(noise)res: %d\n", int(res))

	return int(res)
}

func executeOp(env *C.JNIEnv, jOp0 C.jbyteArray, jOp0Len C.jint,
	jOp1 C.jbyteArray, jOp1Len C.jint, evaluator bfv.Evaluator, opType int, bfvParams bfv.Parameters) C.jbyteArray {

	// deserialize op
	op0Bytes := jBytesToBytes(env, jOp0, jOp0Len)
	op0 := util.BytesToCiphertext(op0Bytes, bfvParams)
	op1Bytes := jBytesToBytes(env, jOp1, jOp1Len)
	op1 := util.BytesToCiphertext(op1Bytes, bfvParams)

	// execute
	res := util.ExecuteOp(evaluator, op0, op1, opType)

	// output
	resBytes, _ := res.MarshalBinary()
	r := buildJByteArray(env, resBytes)

	return r
}

func buildJByteArray(env *C.JNIEnv, res []byte) C.jbyteArray {
	var cOutput *C.char = C.CString(string(res))
	defer C.free(unsafe.Pointer(cOutput))
	r := C.fromCByteArray(env, cOutput, C.int(len(res)))

	return r
}

func jBytesToBytes(env *C.JNIEnv, jOp0 C.jbyteArray, jOp0Len C.jint) []byte {
	cOp0 := C.getCByteArray(env, jOp0)
	op0 := C.GoBytes(unsafe.Pointer(cOp0), jOp0Len)
	defer C.releaseCByteArray(env, jOp0, cOp0)

	return op0
}

func evaluatorWithRK(params bfv.Parameters, rKey *rlwe.RelinearizationKey) bfv.Evaluator {
	evk := rlwe.NewEvaluationKeySet()
	if rKey != nil {
		evk.RelinearizationKey = rKey
	}

	evaluator := bfv.NewEvaluator(params, evk)

	return evaluator
}
