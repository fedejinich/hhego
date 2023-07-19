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

There's an experimental script that is only tied to my local dev, it can be used to compile shared-library and replace it in Java project. You can adapt it to your needs :)

To run the script:

```bash
./build_jni.sh
```
