# Cropty

A little library for doing encryption using a combination of RSA and AEP, using the
[cryptonite](https://hackage.haskell.org/package/cryptonite) library for cryptography.

```haskell
import Cropty

main = do
  privateKey <- generatePrivateKey KeySize1024
  secret <- encrypt (privateToPublic privateKey) "Hello!"
  decoded <- decrypt privateKey secret
  assert (secret == decoded)
```
