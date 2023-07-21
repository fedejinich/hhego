package main

// #include <jni.h>
// #include <stdlib.h>
// static jbyte* getCByteArray(JNIEnv *env, jbyteArray input) {
//     return (*env)->GetByteArrayElements(env, input, NULL);
// }
// static void releaseCByteArray(JNIEnv *env, jbyteArray input, jbyte* cData) {
//     (*env)->ReleaseByteArrayElements(env, input, cData, 0);
// }
// static void setCByteArray(JNIEnv *env, char *input, jint len, jbyteArray output) {
//	   (*env)->SetByteArrayRegion(env, output, 0, len, input);
// }
// static jbyteArray fromCByteArray(JNIEnv *env, char *input, jint len) {
//     jbyteArray result=(*env)->NewByteArray(env, len);
//	   (*env)->SetByteArrayRegion(env, result, 0, len, input);
//	   return result;
// }
import "C"
import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"unsafe"
)

func main() {} // a dummy function

//export Java_org_rsksmart_BFV_foo
func Java_org_rsksmart_BFV_foo(env *C.JNIEnv, clazz C.jclass) C.jint {
	fmt.Println("foo()")
	return 1
}

//export Java_org_rsksmart_BFV_add
func Java_org_rsksmart_BFV_add(env *C.JNIEnv, obj C.jobject, jOp0 C.jbyteArray, jOp0Len C.jint,
	jOp1 C.jbyteArray, jOp1Len C.jint) C.jbyteArray {

	// deserialize
	op0Bytes := deserializeOp(env, jOp0, jOp0Len)
	op1Bytes := deserializeOp(env, jOp1, jOp1Len)

	// add
	res := Evaluator.AddNew(opCiphertext(op0Bytes), opCiphertext(op1Bytes))

	// output
	resBytes, _ := res.MarshalBinary()
	var cOutput *C.char = C.CString(string(resBytes)) // todo(fedejinich) will string always work as expected?
	defer C.free(unsafe.Pointer(cOutput))
	r := C.fromCByteArray(env, cOutput, C.int(len(resBytes)))

	return r
}

func opCiphertext(bytes []byte) *rlwe.Ciphertext {
	ct := bfv.NewCiphertext(BfvParams, 1, BfvParams.MaxLevel())
	ct.UnmarshalBinary(bytes)

	return ct
}

func deserializeOp(env *C.JNIEnv, jOp0 C.jbyteArray, jOp0Len C.jint) []byte {
	cOp0 := C.getCByteArray(env, jOp0)
	op0 := C.GoBytes(unsafe.Pointer(cOp0), jOp0Len)
	defer C.releaseCByteArray(env, jOp0, cOp0)
	return op0
}

func evaluatorBy(params bfv.Parameters, secretKey *rlwe.SecretKey, rKey *rlwe.RelinearizationKey) bfv.Evaluator {
	evk := rlwe.NewEvaluationKeySet()
	evk.RelinearizationKey = rKey
	evaluator := bfv.NewEvaluator(params, evk)

	return evaluator
}

////export Java_org_rsksmart_BFV_encrypt
//func Java_org_rsksmart_BFV_encrypt(env *C.JNIEnv, obj C.jobject, jData C.jbyteArray, dataLen C.jint) C.jbyteArray {
//	fmt.Println("encrypt()")
//
//	// deserialize
//	cData := C.getCByteArray(env, jData)
//	deserialized := C.GoBytes(unsafe.Pointer(cData), dataLen)
//	defer C.releaseCByteArray(env, jData, cData)
//
//	// encrypt
//	data := util.BytesToUint64(deserialized)
//	pt := bfv.NewPlaintext(BfvParams, BfvParams.MaxLevel())
//	bfv.NewEncoder(BfvParams).Encode(data, pt)
//	ct := bfv.NewEncryptor(BfvParams, SecretKey).EncryptNew(pt)
//
//	// to bytes
//	ctBytes, err := ct.MarshalBinary()
//	if err != nil {
//		panic("couldn't serialize ctBytes message") // todo(fedejinich) this is not ok, should return a byte array
//	}
//
//	SavedCt = ct.CopyNew() // todo(fedejinich) remove this
//	SavedPt = pt           // todo(fedejinich) remove this
//	DecryptedPt = bfv.NewDecryptor(BfvParams, SecretKey).DecryptNew(ct)
//
//	// output
//	var cOutput *C.char = C.CString(string(ctBytes))
//	defer C.free(unsafe.Pointer(cOutput))
//	r := C.fromCByteArray(env, cOutput, C.int(len(ctBytes)))
//
//	// some tests (will remove them)
//	//cDataR := C.getCByteArray(env, r)
//	//sliceR := C.GoBytes(unsafe.Pointer(cDataR), C.int(len(ctBytes)))
//	//defer C.releaseCByteArray(env, r, cDataR)
//	//ctR := bfv.NewCiphertext(bfvParams, ct.Degree(), ct.Level())
//	//ctR.UnmarshalBinary(sliceR)
//	//if !ctR.Equal(ct) {
//	//	panic("encoded cualquier verga en jbyteArray")
//	//}
//	//fmt.Println("decrypt bien piola")
//
//	return r
//}

////export Java_org_rsksmart_BFV_decrypt
//func Java_org_rsksmart_BFV_decrypt(env *C.JNIEnv, obj C.jobject, encrypted C.jbyteArray, encryptedLen C.jint, messageLegnth C.jint) C.jbyteArray {
//	fmt.Println("decrypt()")
//
//	// deserialize from Java to Go
//	cData := C.getCByteArray(env, encrypted)
//	slice := C.GoBytes(unsafe.Pointer(cData), encryptedLen)
//	defer C.releaseCByteArray(env, encrypted, cData)
//
//	decryptor := bfv.NewDecryptor(BfvParams, SecretKey)
//
//	// load ct
//	ct := bfv.NewCiphertext(BfvParams, 1, BfvParams.MaxLevel())
//	err := ct.UnmarshalBinary(slice)
//	if err != nil {
//		panic("decrypt malo malo")
//	}
//	if SavedCt != nil && !SavedCt.Equal(ct) {
//		panic("todo mal")
//	}
//
//	// decrypt
//	pt := decryptor.DecryptNew(ct)
//
//	if SavedPt != nil && !SavedPt.Equal(pt) {
//		s, _ := SavedPt.MarshalBinary()
//		p, _ := pt.MarshalBinary()
//		d, _ := DecryptedPt.MarshalBinary()
//		fmt.Println("saved pt")
//		fmt.Println(s[:100])
//		fmt.Println("pt")
//		fmt.Println(p[:100])
//		fmt.Println("decrypted pt")
//		fmt.Println(d[:100])
//		fmt.Println(len(s))
//		fmt.Println(len(p))
//
//		panic("diferente pt")
//	}
//
//	//decoded := bfv.NewEncoder(BfvParams).DecodeUintNew(pt)[:messageLegnth]
//	decoded := bfv.NewEncoder(BfvParams).DecodeUintNew(pt)
//	decrypted := util.Uint64ToBytes(decoded)[:messageLegnth]
//
//	fmt.Println(decrypted)
//	// todo(fedejinich) maybe we can just return the []uint64 and deal with conv on java
//
//	// output
//	var cOutput *C.char = C.CString(string(decrypted))
//	defer C.free(unsafe.Pointer(cOutput))
//	decryptedJbyteArray := C.fromCByteArray(env, cOutput, C.int(len(decrypted)))
//
//	// some tests (will remove them)
//	//cDataR := C.getCByteArray(env, decryptedJbyteArray)
//	//sliceR := C.GoBytes(unsafe.Pointer(cDataR), C.int(len(encryptedOutput)))
//	//defer C.releaseCByteArray(env, decryptedJbyteArray, cDataR)
//	//ctR := bfv.NewCiphertext(bfvParams, ct.Degree(), ct.Level())
//	//ctR.UnmarshalBinary(sliceR)
//	//if !ctR.Equal(ct) {
//	//	panic("encoded cualquier verga en jbyteArray")
//	//}
//	//fmt.Println("decrypt bien piola")
//
//	return decryptedJbyteArray
//}

// todo(fedejinich) sk shouldn't be genreated on server side :)
//var SecretKey, _ = bfv.NewKeyGenerator(BfvParams).GenKeyPairNew()

// todo(fedejinich) should handle errors on this case
//var BfvParams, _ = bfv.NewParametersFromLiteral(bfv.PN15QP827pq)
//var SavedCt *rlwe.Ciphertext
//var SavedPt *rlwe.Plaintext
//var DecryptedPt *rlwe.Plaintext

var ParamsLiteral = bfv.PN15QP827pq
var BfvParams, _ = bfv.NewParametersFromLiteral(ParamsLiteral)
var KeyGenerator = bfv.NewKeyGenerator(BfvParams)
var SecretKey, _ = KeyGenerator.GenKeyPairNew()
var RKey = KeyGenerator.GenRelinearizationKeyNew(SecretKey)
var Evaluator = evaluatorBy(BfvParams, SecretKey, RKey)
