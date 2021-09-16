{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE BlockArguments #-}
module Main where

import Cropty
import Control.Monad.IO.Class (liftIO)
import Hedgehog
import Hedgehog.Gen
import Hedgehog.Range
import Control.Monad (guard)

main :: IO ()
main = do
  keypairs <- sequence
    [ (\private -> (private, privateToPublic private)) <$> generatePrivateKey s
    | Just s <- keySizeFromInt <$> [256, 512]
    ]
  let
    nTests = 10
    roundTrip gen = withTests nTests $ property do
      (privateKey, publicKey) <- forAll (element keypairs)
      x <- forAll gen
      msg <- liftIO (encrypt publicKey x)
      y <- liftIO (decrypt privateKey msg)
      x === y
    signAndVerify gen = withTests nTests $ property do
      (privateKey, publicKey) <- forAll (element keypairs)
      x <- forAll gen
      sig <- liftIO (sign privateKey x)
      assert (verify publicKey x sig)
  guard =<< checkParallel (Group "Encryption/Decryption" [
        ("Encrypt/Decrypt UTF-8",
          roundTrip (utf8 (linearFrom 0 1000 10000) unicodeAll)
        )
      , ("Encrypt/Decrypt Bytes",
          roundTrip (bytes (linearFrom 0 1000 10000))
        )
      , ("Encrypt/Decrybt Trailing Zeros",
          roundTrip ((<>) <$> bytes (linearFrom 0 1000 10000) <*> pure "\0\0\0\0\0\0")
        )
      , ("Encrypt/Decrypt Leading Zeros",
          roundTrip ((<>) <$> pure "\0\0\0\0\0\0" <*> bytes (linearFrom 0 1000 10000))
        )
    ])
  guard =<< checkParallel (Group "Signing/Verification" [
        ("Sign/Verify UTF-8",
          signAndVerify (utf8 (linearFrom 0 1000 10000) unicodeAll)
        )
      , ("Sign/Verify Bytes",
          signAndVerify (bytes (linearFrom 0 1000 10000))
        )
      , ("Sign/Verify: Trailing Zeros",
          roundTrip ((<>) <$> bytes (linearFrom 0 1000 10000) <*> pure "\0\0\0\0\0\0")
        )
      , ("Sign/Verify: Leading Zeros",
          roundTrip ((<>) <$> pure "\0\0\0\0\0\0" <*> bytes (linearFrom 0 1000 10000))
        )
    ])
      
