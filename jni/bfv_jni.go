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

func internalExecute(env *C.JNIEnv, jOp0 C.jbyteArray, jOp0Len C.jint,
	jOp1 C.jbyteArray, jOp1Len C.jint, evaluator bfv.Evaluator, opType int) C.jbyteArray {

	// deserialize
	op0Bytes := deserializeJByteArray(env, jOp0, jOp0Len)
	op1Bytes := deserializeJByteArray(env, jOp1, jOp1Len)

	// execute
	res := util.ExecuteOp(evaluator, opCiphertext(op0Bytes), opCiphertext(op1Bytes), opType)

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
