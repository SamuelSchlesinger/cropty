# Cropty

A little tool for doing encryption using a combination of RSA and AEP, using the
[cryptonite](https://hackage.haskell.org/package/cryptonite) library for cryptography
and [commander-cli](https://hackage.haskell.org/package/commander-cli) for its CLI
interface.

It is meant for use with very large files. I've tested it on a 6 Gigabyte file and it
works within seconds for all functions.

## Installation

To install, run the following in this directory:

```bash
cabal install --installdir=.
```

## Example Usage

```bash
$ export IDENTITY_FILE=my_identity
$ cropty identity populate -s 512
$ echo "Hello, world! This is my secret message" > message
$ cropty encrypt my_identity.public message.encrypted message
$ cropty decrypt message.encrypted message.decrypted
$ cat message.decrypted

$ cropty sign message.encrypted message.signature
$ cropty verify message.encrypted message.signature my_identity.public
```

```bash
$ cropty help

usage:
name: cropty
|
+- subprogram: help
|
+- description: A CLI for simple cryptographic tasks.
|
`- required env: IDENTITY_FILE :: [Char], the environment variable containing the filename of my private key, with my public key located at $IDENTITY_FILE.public
   |
   +- subprogram: identity
   |  |
   |  `- subprogram: populate
   |     |
   |     +- description: Populate the IDENTITY_FILE location with a new RSA private key, writing the public key to IDENTITY_FILE.public
   |     |
   |     `- option: -s <key-size :: Int>, the size of your RSA key pair (e.g. 1024, 2048, 4096), defaulting to 2048
   |
   +- subprogram: encrypt
   |  |
   |  +- description: Encrypt a file for decryption by someone with the private key matching the public key you pass in.
   |  |
   |  `- argument: public-key-filepath :: [Char], the file where your friend's public key is loaded
   |     |
   |     `- argument: destination-filepath :: [Char], the file your encrypted message will be written to
   |        |
   |        `- argument: plaintext-filepath :: [Char], the file containing the plaintext you want to encrypt
   |
   +- subprogram: decrypt
   |  |
   |  +- description: Decrypt a file encrypted for you with your private key.
   |  |
   |  `- argument: encrypted-filename :: [Char], the file which is currently encrypted
   |     |
   |     `- argument: decrypted-filename :: [Char], the file your plaintext will be written to
   |
   +- subprogram: sign
   |  |
   |  +- description: Sign a file with your private key.
   |  |
   |  `- argument: filename-to-sign :: [Char], the file whose contents you will sign
   |     |
   |     `- argument: signature-filename :: [Char], the file where you will write out the signature
   |
   `- subprogram: verify
      |
      +- description: Verify that a signature belongs to the owner of the private key associated to the one you've passed in
      |
      `- argument: filename-signed :: [Char], the file which was signed
         |
         `- argument: signature-filename :: [Char], the file with the signature
            |
            `- argument: signer-pubkey :: [Char], the file containing the public key of who produced this signature by signing this file
```
