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