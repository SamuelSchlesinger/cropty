{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
module App (main) where

import Options.Commander
import System.Directory (doesFileExist)
import Cropty
import UnliftIO.IO.File
import System.IO (hPutStrLn, stderr)
import qualified Data.ByteString.Char8 as ByteString.Char8
import qualified Data.ByteString.Lazy as ByteString.Lazy
import qualified Data.ByteString as ByteString
import qualified Data.Binary as Binary

main :: IO ()
main = command_ $ toplevel @"cropty" program
  where
    program = description @"A CLI for simple cryptographic tasks." $
      annotated @"the environment variable containing the filename of my private key, with my public key located at $IDENTITY_FILE.public" $
      env @"IDENTITY_FILE" $ \identityFile ->
      sub @"identity"
        ( sub @"populate"
        $ description @"Populate the IDENTITY_FILE location with a new RSA private key, writing the public key to IDENTITY_FILE.public"
        $ opt @"s" @"key-size" $ \keySize -> raw (populateIdentity keySize identityFile)
        )
      <+> sub @"encrypt"
        ( description @"Encrypt a file for decryption by someone with the private key matching the public key you pass in."
        $ annotated @"the file where your friend's public key is loaded" $ arg @"public-key-filepath" $ \to ->
          annotated @"the file your encrypted message will be written to" $ arg @"destination-filepath" $ \dest ->
          annotated @"the file containing the plaintext you want to encrypt" $ arg @"plaintext-filepath" (raw . encryptFile dest to))
      <+> sub @"decrypt"
        ( description @"Decrypt a file encrypted for you with your private key."
        $ annotated @"the file which is currently encrypted" $ arg @"encrypted-filename" $ \encFilepath ->
          annotated @"the file your plaintext will be written to" $ arg @"decrypted-filename" (raw . decryptFile encFilepath identityFile)
        )
      <+> sub @"sign"
        ( description @"Sign a file with your private key."
        $ annotated @"the file whose contents you will sign" $ arg @"filename-to-sign" $ \fileToSign ->
          annotated @"the file where you will write out the signature" $ arg @"signature-filename" (raw . signFile identityFile fileToSign)
        )
      <+> sub @"verify"
        ( description @"Verify that a signature belongs to the owner of the private key associated to the one you've passed in"
        $ annotated @"the file which was signed" $ arg @"filename-signed" $ \fileSigned ->
          annotated @"the file with the signature" $ arg @"signature-filename" $ \signatureFilename ->
          annotated @"the file containing the public key of who produced this signature by signing this file" $ arg @"signer-pubkey" (raw . verifySignature fileSigned signatureFilename)
        )
    populateIdentity :: Maybe Int -> FilePath -> IO ()
    populateIdentity (maybe 2048 id -> n) identityFilepath = do
      doesFileExist identityFilepath >>= \case
        True -> putStrLn "You already have a populated identity file. Delete it manually if you would like to generate a new one."
        False -> do
          priv <- generatePrivateKey n
          writeBinaryFileDurableAtomic identityFilepath (ByteString.Char8.pack $ show priv)
          writeBinaryFileDurableAtomic (identityFilepath <> ".public") (ByteString.Char8.pack $ show (privateToPublic priv))
    encryptFile :: FilePath -> FilePath -> FilePath -> IO ()
    encryptFile destFilepath toFilePath msgFilepath = do
      pub <- read <$> readFile toFilePath
      secretMsg <- ByteString.readFile msgFilepath
      msg <- encrypt pub secretMsg
      writeBinaryFileDurableAtomic destFilepath (ByteString.Lazy.toStrict $ Binary.encode msg)
    decryptFile :: FilePath -> FilePath -> FilePath -> IO ()
    decryptFile msgFilepath identityFilepath destFilepath = do
      priv <- read <$> readFile identityFilepath
      msg <-  Binary.decode <$> ByteString.Lazy.readFile msgFilepath
      decrypted <- decrypt priv msg
      writeBinaryFileDurableAtomic destFilepath decrypted
    signFile :: FilePath -> FilePath -> FilePath -> IO ()
    signFile identityFilepath encFilepath signatureFilepath = do
      priv <- read <$> readFile identityFilepath
      msg <- ByteString.readFile encFilepath
      signature <- sign priv msg
      writeBinaryFileDurableAtomic signatureFilepath signature
    verifySignature :: FilePath -> FilePath -> FilePath -> IO ()
    verifySignature fileSigned signatureFilename signerFilename = do
      pub <- read <$> readFile signerFilename
      signature <- ByteString.readFile signatureFilename
      msg <- ByteString.readFile fileSigned
      if verify pub msg signature then
        putStrLn "Signature valid."
      else
        putStrLn "Signature invalid."
