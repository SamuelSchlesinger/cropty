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
  let
    publicKey = privateToPublic privateKey
    roundTrip gen = withTests 10 $ property do
      x <- forAll gen
      msg <- liftIO (encrypt publicKey x)
      y <- liftIO (decrypt privateKey msg)
      x === y
  guard =<< checkParallel (Group "Cropty" [
      ("Round Trip UTF-8", roundTrip (utf8 (linearFrom 0 1000 10000) unicodeAll))
    -- , ("Trailing Zeros", roundTrip (pure "\0\0\0\0\0\0"))
    ])
      
