CGO_CFLAGS = "-I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I$(JAVA_HOME)/include/darwin"

macos:
	CGO_ENABLED=1 CGO_CFLAGS=$(CGO_CFLAGS) GOOS=darwin GOARCH=amd64 go build -trimpath -buildmode=c-shared -o libbfv_jni.dylib -v bfv_jni.go

clean:
	rm -f libbfv_jni.dylib libbfv_jni.h

