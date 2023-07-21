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

var ParamsLiteral = bfv.PN15QP827pq // todo(fedejinich) should we parametrize this
var BfvParams, _ = bfv.NewParametersFromLiteral(ParamsLiteral)
var KeyGenerator = bfv.NewKeyGenerator(BfvParams)
var SecretKey, _ = KeyGenerator.GenKeyPairNew()             // todo(fedejinich) this will be parametrized
var RKey = KeyGenerator.GenRelinearizationKeyNew(SecretKey) // todo(fedejinich) this will be calculated on each call
var Evaluator = evaluatorBy(BfvParams, SecretKey, RKey)     // todo(fedejinich) same for this

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
