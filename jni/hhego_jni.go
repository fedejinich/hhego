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

func main() {} // a dummy function

//export Java_org_fedejinich_GoJNI_foo
func Java_org_fedejinich_GoJNI_foo(env *C.JNIEnv, clazz C.jclass) C.jint {
	println("foo() from go")
	return 1
}
