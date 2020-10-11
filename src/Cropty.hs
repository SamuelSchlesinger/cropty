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

generatePrivateKey :: Int -> IO PrivateKey
generatePrivateKey n = (PrivateKey . snd) <$> RSA.generate n 65537

encryptSmall :: PublicKey -> ByteString -> IO (Either RSA.Error ByteString)
encryptSmall (PublicKey pub) message = RSA.OAEP.encrypt (RSA.OAEP.defaultOAEPParams Hash.SHA512) pub message

decryptSmall :: PrivateKey -> ByteString -> IO (Either RSA.Error ByteString)
decryptSmall (PrivateKey priv) message = RSA.OAEP.decryptSafer (RSA.OAEP.defaultOAEPParams Hash.SHA512) priv message

-- Generate a 32 byte bytestring, encrypt it using RSA for our
-- destination, then use it as the input to encrypt, using AES, the 
-- message we actually wanted to encrypt.

newtype Key = Key { keyBytes :: ByteString }

generateKey :: IO Key
generateKey = Key <$> Random.getRandomBytes 32

data Message = Message
  { encryptedKey :: ByteString
  , encryptedBytes :: ByteString
  } deriving (Show, Read, Generic, Binary)

data EncryptionException = EncryptionException String
  deriving Show

instance Exception EncryptionException

encrypt :: PublicKey -> ByteString -> IO Message
encrypt publicKey message = do
  let paddedMessage = Padding.pad (Padding.ZERO 16) message
  key <- generateKey
  encryptSmall publicKey (keyBytes key) >>= \case
    Left rsaError -> throwIO $ EncryptionException (show rsaError)
    Right encryptedKey -> case Cipher.cipherInit (keyBytes key) of
      Error.CryptoFailed e -> throwIO $ EncryptionException (show e)
      Error.CryptoPassed (c :: AES.AES256) -> do
        let encryptedBytes = Cipher.ecbEncrypt c paddedMessage
        pure Message{encryptedKey, encryptedBytes}

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
        -- TODO(sam) dropWhileEnd in bytestring 0.11 should be used here,
        -- this is depressingly bad ATM
        pure $ ByteString.reverse (ByteString.dropWhile (== 0) (ByteString.reverse decryptedBytes))

data SignatureException = SignatureException String
  deriving Show

instance Exception SignatureException

sign :: PrivateKey -> ByteString -> IO ByteString
sign (PrivateKey privateKey) bs = RSA.PSS.signSafer (RSA.PSS.defaultPSSParams Hash.SHA512) privateKey bs >>= either (throwIO . SignatureException . show) pure

verify :: PublicKey -> ByteString -> ByteString -> Bool
verify (PublicKey pubKey) bs sig = RSA.PSS.verify (RSA.PSS.defaultPSSParams Hash.SHA512) pubKey bs sig
