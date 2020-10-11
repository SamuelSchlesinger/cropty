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
  privateKey <- generatePrivateKey 1024
  privateKey' <- generatePrivateKey 1024
  let
    publicKey = privateToPublic privateKey
    publicKey' = privateToPublic privateKey'
    roundTrip gen = withTests 10 $ property do
      x <- forAll gen
      msg <- liftIO (encrypt publicKey x)
      y <- liftIO (decrypt privateKey msg)
      x === y
    signAndVerify gen = withTests 10 $ property do
      x <- forAll gen
      sig <- liftIO (sign privateKey x)
      assert (verify publicKey x sig)
      assert (not (verify publicKey' x sig))
  guard =<< checkParallel (Group "Encryption/Decryption" [
        ("Round Trip UTF-8",
          roundTrip (utf8 (linearFrom 0 1000 10000) unicodeAll)
        )
      , ("Round Trip Bytes",
          roundTrip (bytes (linearFrom 0 1000 10000))
        )
      , ("Padding CornerCase: Trailing Zeros",
          roundTrip ((<>) <$> bytes (linearFrom 0 1000 10000) <*> pure "\0\0\0\0\0\0")
        )
      , ("Padding Corner Case: Leading Zeros",
          roundTrip ((<>) <$> pure "\0\0\0\0\0\0" <*> bytes (linearFrom 0 1000 10000))
        )
    ])
  guard =<< checkParallel (Group "Signing/Verification" [
        ("Sign and Verify UTF-8",
          signAndVerify (utf8 (linearFrom 0 1000 10000) unicodeAll)
        )
      , ("Sign and Verify Bytes",
          signAndVerify (bytes (linearFrom 0 1000 10000))
        )
      , ("Sign and Verify: Trailing Zeros",
          roundTrip ((<>) <$> bytes (linearFrom 0 1000 10000) <*> pure "\0\0\0\0\0\0")
        )
      , ("Sign and Verify: Leading Zeros",
          roundTrip ((<>) <$> pure "\0\0\0\0\0\0" <*> bytes (linearFrom 0 1000 10000))
        )
    ])
      
