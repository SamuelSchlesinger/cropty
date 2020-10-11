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
    program = description @"cropty is a command line program for encryption and decryption" $
      env @"IDENTITY_FILE" $ \identityFile ->
      sub @"identity" (sub @"populate" (raw (populateIdentity identityFile)))
      <+> sub @"encrypt" (arg @"to-filename" $ \to -> arg @"dest-filename" $ \dest -> arg @"message-filename" (raw . encryptFile dest to))
      <+> sub @"decrypt" (arg @"encrypted-filename" $ \encFilepath -> arg @"decrypted-filename" (raw . decryptFile encFilepath identityFile))
    populateIdentity :: FilePath -> IO ()
    populateIdentity identityFilepath = do
      doesFileExist identityFilepath >>= \case
        True -> putStrLn "You already have a populated identity file. Delete it manually if you would like to generate a new one."
        False -> do
          priv <- generatePrivateKey
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
