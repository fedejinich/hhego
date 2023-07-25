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

## Benchmarks

Benchmarks can be found at `~/benchmark` folder. 

WIP

## Build for Java as Shared Library

This project can be build as a shared library to be used from a Java application. To build as shared library go to `PROJECT_ROOT/jni` and run

```bash
make macos

# or if you're using linux

make linux # todo(fedejinich) this is not implemented yet
```

This will set the right flags and build it for a `amd64` architecture. Then the output will be on the same `jni` folder.

### Experimental script 

There are two experimental script:
1. To compile and inject the new library into the `hhejava` project

```bash
./build_jni.sh
```


2. To generate and replace test data into the `hhejava` project.

```bash
./generate_test_cases.sh
```


To run the script:

```bash
./build_jni.sh
```
