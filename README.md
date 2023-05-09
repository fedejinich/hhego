# hhego

hhego is a Go library specifically designed to implement hybrid homomorphic encryption schemes. This innovative library merges the advantages of symmetric and homomorphic encryption methodologies, employing PASTA as the symmetric cipher and BFV as the homomorphic cipher. The outcome is a hybrid homomorphic encryption system that ensures secure computation on encrypted data while preserving the efficiency of symmetric encryption for large-scale processing tasks.

## Overview of Hybrid Homomorphic Encryption

Homomorphic encryption (HE) permits direct computations on encrypted data without necessitating decryption. This capability is incredibly useful for applications centered on privacy, where data confidentiality is a critical requirement. Yet, traditional HE can be computationally intensive compared to symmetric encryption schemes.

Our solution, hybrid homomorphic encryption, addresses this problem. It blends the speed of symmetric encryption with the privacy-preserving capacities of homomorphic encryption. In this library, we utilize PASTA for quick encryption and decryption, and BFV for secure computations on encrypted data.

## Examples

Examples of how to use this library can be found in the 'examples' folder. Currently, it only contains examples for a single party use case. More examples demonstrating different use cases will be added in the future.

## Dependencies

This library depends on the following packages:

- [lattigo v4](https://github.com/tuneinsight/lattigo): A library for lattice-based multi-party homomorphic encryption in Go
