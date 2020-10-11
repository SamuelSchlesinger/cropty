# Cropty

A little tool for doing encryption using a combination of RSA and AEP.

```
usage:
name: cropty
|
+- subprogram: help
|
+- description: cropty is a command line program for encryption and decryption
|
`- required env: IDENTITY_FILE :: [Char]
   |
   +- subprogram: identity
   |  |
   |  `- subprogram: populate
   |     |
   |     `- option: -s <key-size :: Int>
   |
   +- subprogram: encrypt
   |  |
   |  `- argument: to-filename :: [Char]
   |     |
   |     `- argument: dest-filename :: [Char]
   |        |
   |        `- argument: message-filename :: [Char]
   |
   +- subprogram: decrypt
   |  |
   |  `- argument: encrypted-filename :: [Char]
   |     |
   |     `- argument: decrypted-filename :: [Char]
   |
   +- subprogram: sign
   |  |
   |  `- argument: filename-to-sign :: [Char]
   |     |
   |     `- argument: signature-filename :: [Char]
   |
   `- subprogram: verify
      |
      `- argument: filename-signed :: [Char]
         |
         `- argument: signature-filename :: [Char]
            |
            `- argument: signer-pubkey :: [Char]
```
