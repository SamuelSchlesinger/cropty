{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE LambdaCase #-}
module Cropty where

import Data.ByteString (ByteString)
import GHC.Generics (Generic)
import Data.Binary (Binary)
import Control.Monad (guard)
import Control.Exception (SomeException, catch, Exception, throwIO)
import qualified Crypto.Cipher.AES as AES
import qualified Crypto.Cipher.Types as Cipher
import qualified Crypto.Data.Padding as Padding
import qualified Crypto.Error as Error
import qualified Crypto.Hash.Algorithms as Hash
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.OAEP as RSA.OAEP
import qualified Crypto.PubKey.RSA.PSS as RSA.PSS
import qualified Crypto.Random as Random
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString.Char8

newtype PrivateKey = PrivateKey
  { privateKey :: RSA.PrivateKey }
  deriving (Show, Read, Eq)

data PublicKey = PublicKey
  { publicKey :: RSA.PublicKey }
  deriving (Show, Read, Eq)

privateToPublic :: PrivateKey -> PublicKey
privateToPublic = PublicKey . RSA.private_pub . privateKey

data GenerationException = GenerationException String
  deriving Show

instance Exception GenerationException

generatePrivateKey :: Int -> IO PrivateKey
generatePrivateKey n =
    if n >= 256
      then (PrivateKey . snd) <$> RSA.generate n 65537
      else throwIO (GenerationException "size of key must be greater than or equal to 256")

encryptSmall :: PublicKey -> ByteString -> IO (Either RSA.Error ByteString)
encryptSmall (PublicKey pub) message =
    RSA.OAEP.encrypt (RSA.OAEP.defaultOAEPParams Hash.SHA512) pub message

decryptSmall :: PrivateKey -> ByteString -> IO (Either RSA.Error ByteString)
decryptSmall (PrivateKey priv) message =
    RSA.OAEP.decryptSafer (RSA.OAEP.defaultOAEPParams Hash.SHA512) priv message

newtype Key =
    Key { keyBytes :: ByteString }

generateKey :: IO Key
generateKey =
    Key <$> Random.getRandomBytes 32

data Message = Message
  { encryptedKey :: ByteString
  , encryptedBytes :: ByteString
  } deriving (Show, Read, Generic, Binary)

data EncryptionException = EncryptionException String
  deriving Show

instance Exception EncryptionException

encrypt :: PublicKey -> ByteString -> IO Message
encrypt publicKey message = do
  key <- generateKey
  encryptSmall publicKey (keyBytes key) >>= \case
    Left rsaError -> throwIO $ EncryptionException (show rsaError)
    Right encryptedKey -> case Cipher.cipherInit (keyBytes key) of
      Error.CryptoFailed e -> throwIO $ EncryptionException (show e)
      Error.CryptoPassed (c :: AES.AES256) -> do
        let encryptedBytes = Cipher.ecbEncrypt c paddedMessage
        pure Message{encryptedKey, encryptedBytes}
  where
    paddingSize =
      16 - (ByteString.length message + 1) `mod` 16
    paddedMessage =
      ByteString.concat
        [ ByteString.singleton (fromIntegral paddingSize)
        , ByteString.replicate paddingSize 0
        , message
        ]

data DecryptionException = DecryptionException String
  deriving Show

instance Exception DecryptionException

decrypt :: PrivateKey -> Message -> IO ByteString
decrypt privateKey Message{encryptedKey, encryptedBytes} = do
  decryptSmall privateKey encryptedKey >>= \case
    Left rsaError -> throwIO $ DecryptionException (show rsaError)
    Right decryptedKey -> case Cipher.cipherInit decryptedKey of
      Error.CryptoFailed e -> throwIO $ DecryptionException (show e)
      Error.CryptoPassed (c :: AES.AES256) -> do
        let decryptedBytes = Cipher.ecbDecrypt c encryptedBytes
        if ByteString.length decryptedBytes > 0 then do
          let paddingSize = fromIntegral (ByteString.index decryptedBytes 0)
          pure $ snd (ByteString.splitAt (paddingSize + 1) decryptedBytes)
        else throwIO (DecryptionException "Not encrypted by Cropty")

data SignatureException = SignatureException String
  deriving Show

instance Exception SignatureException

sign :: PrivateKey -> ByteString -> IO ByteString
sign (PrivateKey privateKey) bs =
    RSA.PSS.signSafer
      (RSA.PSS.defaultPSSParams Hash.SHA512)
      privateKey
      bs
    >>= either (throwIO . SignatureException . show) pure

verify :: PublicKey -> ByteString -> ByteString -> Bool
verify (PublicKey pubKey) bs sig =
    RSA.PSS.verify (RSA.PSS.defaultPSSParams Hash.SHA512) pubKey bs sig
