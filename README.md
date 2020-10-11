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
   |
   +- subprogram: encrypt
   |  |
   |  `- argument: to-filename :: [Char]
   |     |
   |     `- argument: dest-filename :: [Char]
   |        |
   |        `- argument: message-filename :: [Char]
   |
   `- subprogram: decrypt
      |
      `- argument: encrypted-filename :: [Char]
         |
         `- argument: decrypted-filename :: [Char]
```
