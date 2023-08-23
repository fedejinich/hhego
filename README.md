# hhego

hhego is a Go library specifically designed to implement a hybrid homomorphic encryption scheme. 

## Hybrid Homomorphic Scheme

This library merges the advantages of symmetric and homomorphic encryption methodologies, employing PASTA as the symmetric cipher and BFV as the homomorphic cipher. The outcome is a hybrid homomorphic encryption system that ensures secure computation on encrypted data while preserving the efficiency of symmetric encryption for large-scale processing tasks.

## Dependencies

This library depends on the following packages:

- [lattigo v4](https://github.com/tuneinsight/lattigo): A library for lattice-based multi-party homomorphic encryption in Go

## Running the schemes

There are some basic example schemes that can be found and run as regular go tests at `hhe_scheme_test.go`.

```bash
go test hhe_scheme_test.go
```

## Build for Java as Shared Library

This project can be build as a shared library to be used from a Java application. To build as shared library go to `PROJECT_ROOT/jni` and run

```bash
make macos
```

This will set the right flags and build it for a `amd64` architecture. Then the output will be on the same `jni` folder.

### Experimental script 

There are two experimental scripts:
1. To compile and inject the new mac-library into the `hhejava` project

```bash
./build_jni_mac.sh
```


2. To generate and replace test data into the `hhejava` project.

```bash
./generate_test_cases.sh
```