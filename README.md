# hhego
hhego is a Go library for implementing hybrid homomorphic encryption schemes. It combines the strengths of both symmetric and homomorphic encryption techniques by utilizing PASTA as the symmetric cipher and BFV as the homomorphic cipher.
Hybrid homomorphic encryption allows secure computation on encrypted data while maintaining the efficiency of symmetric encryption for large-scale processing tasks.

## Introduction to Hybrid Homomorphic Encryption
Homomorphic encryption (HE) enables computations to be performed directly on encrypted data without the need for decryption. This is particularly useful in privacy-preserving applications where data confidentiality is crucial. However, HE can be computationally expensive compared to traditional symmetric encryption schemes.

Hybrid homomorphic encryption addresses this issue by combining the efficiency of symmetric encryption with the privacy-preserving capabilities of homomorphic encryption. In this library, we use the PASTA symmetric cipher for fast encryption and decryption, and the BFV homomorphic cipher for secure computations on encrypted data.

## Dependencies
- [lattigo v4](https://github.com/tuneinsight/lattigo): a library for lattice-based multiparty homomorphic encryption in Go

## Build
Requirements:
- go 1.19

```bash
go build # todo update this and create a 'build' script
```

## Test

```bash
go test # todo update this and create a 'test' script
```