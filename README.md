# Cropty

A little tool for doing encryption using a combination of RSA and AEP.

```
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
   |     `- option: -s <key-size :: Int>
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
