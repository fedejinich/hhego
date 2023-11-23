# hhego

`hhego` is a monorepo for all Go-based tools used as part of the HHE (Hybrid Homomorphic Encryption) Proof of Concept. 

### Components

- **bfv**: `lattigo` wrapper, designed to create hybrid homomorphic encryption schemes.
- **pasta**: contains PASTA symmetric cipher.
- **js**: A script for generating votes in the `fhBallot` project.
- **jni**: Java bindings to integrate it with `rskj`.
- **workspace**: a place for small tests. 

The goal of `hhego` is to integrate these components with `rskj`, enabling support for hybrid homomorphic encryption on Rootstock.

## Installation and Usage

### JNI

The JNI component enables the use of `bfv` in Java applications, in this PoC we use it to integrate it with `rskj` and use it as a precompiled contract.

To build this library, use the following command:

```bash
make macos
```

The output should be `libbfv_jni.dylib`, a dynamic library for mac.

##### Bash Script

There's also a bash script that builds and copies the output to `rskj`.

```bash
./build_jni_mac.sh
```

### JS 

The JS component includes a Go script designed to generate encrypted votes for the `fhBallot` project. To execute this script, run:

```bash
go run votes.go
```

This script produces a JSON output with the following structure:

```json
{
    "votes": [[1, 0, 0, 0], [0, 1, 0, 0]], // Generated votes
    "votesPasta": [[30447, 62405, 62714, 38763], [30446, 62406, 62714, 38763]], // Encrypted votes using PASTA
    "pastaSK": [1, 1, 1, 1, 1], // BFV-encrypted PASTA secret key
	"rk": [1, 1, 1, 1, 1], // Relinearization key (for converting PASTA votes to BFV votes)
	"bfvSK": [1, 1, 1, 1, 1] // BFV secret key (used for encrypting PASTA SK)
}
```

##### Bash Script

There's also a bash script that builds and copies the output to `rskj`.

```bash
./generate_votes.sh
```
