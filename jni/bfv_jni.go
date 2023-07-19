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
import "C"
import (
	"fmt"
	"github.com/fedejinich/hhego/util"
	"unsafe"
)

func main() {} // a dummy function

//export Java_org_rsksmart_BFV_foo
func Java_org_rsksmart_BFV_foo(env *C.JNIEnv, clazz C.jclass) C.jint {
	fmt.Println("foo() from go")
	return 1
}

//export Java_org_rsksmart_BFV_encrypt
func Java_org_rsksmart_BFV_encrypt(env *C.JNIEnv, obj C.jobject, data C.jbyteArray, dataLen C.jint, encrypted C.jbyteArray) C.jint {
	fmt.Println("encrypt()")
	cData := C.getCByteArray(env, data)
	slice := C.GoBytes(unsafe.Pointer(cData), dataLen)

	fmt.Println(slice)

	if !util.EqualSlices2(slice, []byte{0x0, 0x1, 0x3, 0x4}) {
		return 0
	} else {
		return 1
	}
}
