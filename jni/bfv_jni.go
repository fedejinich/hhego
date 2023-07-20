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
	"github.com/fedejinich/hhego/util"
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

//export Java_org_rsksmart_BFV_encrypt
func Java_org_rsksmart_BFV_encrypt(env *C.JNIEnv, obj C.jobject, data C.jbyteArray, dataLen C.jint) C.jbyteArray {
	fmt.Println("encrypt()")

	// deserialize
	cData := C.getCByteArray(env, data)
	slice := C.GoBytes(unsafe.Pointer(cData), dataLen)
	defer C.releaseCByteArray(env, data, cData)

	bfvParams, encryptor := bfvEncryptor(bfv.PN15QP827pq)

	// encrypt
	pt := bfv.NewPlaintext(bfvParams, bfvParams.MaxLevel())
	bfv.NewEncoder(bfvParams).Encode(util.BytesToUint64(slice), pt)
	fmt.Println("plaintext bfv")
	b, _ := pt.MarshalBinary()
	fmt.Println(b[:100])
	ct := encryptor.EncryptNew(pt)
	encryptedOutput, err := ct.MarshalBinary()
	fmt.Println("ciphertext bfv")
	fmt.Println(encryptedOutput[:100])
	if err != nil {
		panic("couldn't serialize encrypted message") // todo(fedejinich) this is not ok, should return a byte array
	}

	// output
	var cOutput *C.char = C.CString(string(encryptedOutput))
	defer C.free(unsafe.Pointer(cOutput))
	r := C.fromCByteArray(env, cOutput, C.int(len(encryptedOutput)))

	// some tests (will remove them)
	//cDataR := C.getCByteArray(env, r)
	//sliceR := C.GoBytes(unsafe.Pointer(cDataR), C.int(len(encryptedOutput)))
	//defer C.releaseCByteArray(env, r, cDataR)
	//ctR := bfv.NewCiphertext(bfvParams, ct.Degree(), ct.Level())
	//ctR.UnmarshalBinary(sliceR)
	//if !ctR.Equal(ct) {
	//	panic("encoded cualquier verga en jbyteArray")
	//}
	//fmt.Println("decrypt bien piola")

	return r
}

//export Java_org_rsksmart_BFV_decrypt
func Java_org_rsksmart_BFV_decrypt(env *C.JNIEnv, obj C.jobject, encrypted C.jbyteArray, encryptedLen C.jint, messageLegnth C.jint) C.jbyteArray {
	fmt.Println("decrypt()")

	// deserialize
	cData := C.getCByteArray(env, encrypted)
	slice := C.GoBytes(unsafe.Pointer(cData), encryptedLen)
	defer C.releaseCByteArray(env, encrypted, cData)

	fmt.Println("bfv ciphertext")
	fmt.Println(slice[:100])

	bfvParams, decryptor := bfvDecryptor(bfv.PN15QP827pq)

	// decrypt
	ct := bfv.NewCiphertext(bfvParams, 1, bfvParams.MaxLevel())
	err := ct.UnmarshalBinary(slice)
	if err != nil {
		panic("decrypt malo malo")
	}
	decryptedPlaintext := decryptor.DecryptNew(ct)
	fmt.Println("bfv plaintext")
	d, _ := decryptedPlaintext.MarshalBinary()
	fmt.Println(d[:100])

	decrypted := util.Uint64ToBytes(bfv.NewEncoder(bfvParams).DecodeUintNew(decryptedPlaintext))

	if err != nil {
		panic("couldn't serialize bfv plaintext") // todo(fedejinich) this is not ok, should return a byte array
	}

	// output
	fmt.Println("decrypted")
	fmt.Println(decrypted[:100])
	fmt.Println("decrypted after postprocessing")
	fmt.Println(decrypted[:messageLegnth])
	out := decrypted[:messageLegnth]
	var cOutput *C.char = C.CString(string(out))
	defer C.free(unsafe.Pointer(cOutput))
	r := C.fromCByteArray(env, cOutput, C.int(len(out)))

	// some tests (will remove them)
	//cDataR := C.getCByteArray(env, r)
	//sliceR := C.GoBytes(unsafe.Pointer(cDataR), C.int(len(encryptedOutput)))
	//defer C.releaseCByteArray(env, r, cDataR)
	//ctR := bfv.NewCiphertext(bfvParams, ct.Degree(), ct.Level())
	//ctR.UnmarshalBinary(sliceR)
	//if !ctR.Equal(ct) {
	//	panic("encoded cualquier verga en jbyteArray")
	//}
	//fmt.Println("decrypt bien piola")

	return r
}

func bfvEncryptor(params bfv.ParametersLiteral) (bfv.Parameters, rlwe.Encryptor) {
	bfvParams, err := bfv.NewParametersFromLiteral(params)
	if err != nil {
		panic("couldn't initialize bfv") // todo(fedejinich) change this into
	}
	secretKey, _ := bfv.NewKeyGenerator(bfvParams).GenKeyPairNew() // todo(fedejinich) this is not ok, the user must provide a sk
	bfvCipher := bfv.NewEncryptor(bfvParams, secretKey)

	return bfvParams, bfvCipher
}

func bfvDecryptor(params bfv.ParametersLiteral) (bfv.Parameters, rlwe.Decryptor) {
	bfvParams, err := bfv.NewParametersFromLiteral(params)
	if err != nil {
		panic("couldn't initialize bfv") // todo(fedejinich) change this into
	}
	secretKey, _ := bfv.NewKeyGenerator(bfvParams).GenKeyPairNew() // todo(fedejinich) this is not ok, the user must provide a sk
	bfvCipher := bfv.NewDecryptor(bfvParams, secretKey)

	return bfvParams, bfvCipher
}
