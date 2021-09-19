# Cropty

A little library for doing encryption using a combination of RSA and AEP, using the
[cryptonite](https://hackage.haskell.org/package/cryptonite) library for cryptography.

```haskell
ghci> privateKey <- generatePrivateKey KeySize256
ghci> encrypt (privateToPublic privateKey) "Hello" >>= decrypt privateKey
"Hello"
```
