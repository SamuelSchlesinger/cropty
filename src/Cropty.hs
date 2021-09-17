{- |
Name: Cropty
Description: A simplified interface to asymmetric and symmetric cryptography
License: MIT
Copyright: Samuel Schlesinger 2021 (c)
-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE LambdaCase #-}
module Cropty
  ( 
    -- * Asymmetric Encryption
    PrivateKey (PrivateKey, privateKey)
  , privateToPublic
  , PublicKey (PublicKey, publicKey)
    -- ** Efficient Encryption
  , Message (..)
  , encrypt
  , EncryptionException (..)
  , decrypt
  , DecryptionException (..)
    -- ** Digital Signatures
  , Signature (Signature, signatureBytes)
  , sign
  , verify
  , Signed
  , signed
  , signedBy
  , signature
  , signedEncoded
  , mkSigned
  , verifySigned
    -- ** Encrypt/Decrypt Small Strings
  , encryptSmall
  , decryptSmall
    -- ** Supported Key Sizes
  , KeySize (..)
  , keySizeInt
  , keySizeFromInt
    -- ** Key generation
  , generatePrivateKey
  , generatePrivateKeyWithPublicExponent
    -- * Symmetric Encryption
  , Key (Key, keyBytes)
  , generateKey
  , generateKeyOfSize
  , encryptSym
  , SymEncryptionException (..)
  , decryptSym
  , SymDecryptionException (..)
    -- * Errors Re-Exported from Cryptonite
  , RSAError
  , CryptoError (..)
  ) where

import Data.ByteString (ByteString)
import GHC.Generics (Generic)
import Data.Binary (Binary(..), encode)
import qualified Crypto.PubKey.RSA.Types (Error (..))
import Crypto.Error (CryptoError (..))
import Control.Exception (Exception, throwIO)
import qualified Crypto.Cipher.AES as AES
import qualified Crypto.Cipher.Types as Cipher
import qualified Crypto.Error as Error
import qualified Crypto.Hash.Algorithms as Hash
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.OAEP as RSA.OAEP
import qualified Crypto.PubKey.RSA.PSS as RSA.PSS
import qualified Crypto.Random as Random
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LBS

-- |
-- @import qualified Crypto.PubKey.RSA.Types as RSA (Error (..))@
type RSAError = Crypto.PubKey.RSA.Types.Error

-- | A secret identity which one should be very careful about storing
-- and sharing. If others get it, they will be able to read messages
-- intended for you.
newtype PrivateKey = PrivateKey
  { privateKey :: RSA.PrivateKey }
  deriving (Show, Read, Eq)

instance Binary PrivateKey where
  put (PrivateKey p) = do
    put (PublicKey $ RSA.private_pub p)
    put (RSA.private_d p)
    put (RSA.private_p p)
    put (RSA.private_q p)
    put (RSA.private_dP p)
    put (RSA.private_dQ p)
    put (RSA.private_qinv p)
  get = PrivateKey <$>
    ( RSA.PrivateKey
      <$> (publicKey <$> get)
      <*> get
      <*> get
      <*> get
      <*> get
      <*> get
      <*> get
    )

instance Ord PrivateKey where
  compare (PrivateKey p) (PrivateKey p') = compare (PublicKey $ RSA.private_pub p) (PublicKey $ RSA.private_pub p')

-- | A public identity which corresponds to your secret one, allowing
-- you to tell other people how to 'encrypt' things for you. If you 'sign'
-- something with the 'PrivateKey' associated with this public one,
-- someone will be able to verify it was you with your public key.
data PublicKey = PublicKey
  { publicKey :: RSA.PublicKey }
  deriving (Show, Read, Eq)

instance Binary PublicKey where
  put (PublicKey p) = do
    put (RSA.public_size p)
    put (RSA.public_n p)
    put (RSA.public_e p)
  get = PublicKey <$>
    ( RSA.PublicKey
    <$> get
    <*> get
    <*> get
    )

instance Ord PublicKey where
  compare (PublicKey p) (PublicKey p') =
    compare (RSA.public_size p) (RSA.public_size p')
    <> compare (RSA.public_n p) (RSA.public_n p')
    <> compare (RSA.public_e p) (RSA.public_e p')

-- | Get a 'PublicKey' which corresponds to the given 'PrivateKey'
privateToPublic :: PrivateKey -> PublicKey
privateToPublic = PublicKey . RSA.private_pub . privateKey

-- | The various supported key sizes for the underlying RSA implementation
data KeySize = KeySize256 | KeySize512 | KeySize1024 | KeySize2048 | KeySize4096
  deriving (Eq, Ord, Enum, Bounded)

-- | Get the size of the key in the form of an 'Int'
keySizeInt :: KeySize -> Int
keySizeInt k = 2 ^ (fromEnum k + 8)

-- | Get the size of a 
keySizeFromInt :: Int -> Maybe KeySize
keySizeFromInt n
  | n == 256 = Just KeySize256
  | n == 512 = Just KeySize512
  | n == 1024 = Just KeySize1024
  | n == 2048 = Just KeySize2048
  | n == 4096 = Just KeySize4096 
  | otherwise = Nothing

-- | Generate a new 'PrivateKey' of the given 'KeySize'
generatePrivateKey :: KeySize -> IO PrivateKey
generatePrivateKey = generatePrivateKeyWithPublicExponent 65537

-- | Generate a new 'PrivateKey' of the given 'KeySize', providing the RSA public exponent as well.
generatePrivateKeyWithPublicExponent :: Integer -> KeySize -> IO PrivateKey
generatePrivateKeyWithPublicExponent e n = (PrivateKey . snd) <$> RSA.generate (keySizeInt n) e

-- | Encrypt a 'ByteString' of length less than or equal to the 'KeySize'. Skips
-- the symmetric encryption step. For the most part, this should be avoided, but
-- there is no reason not to expose it.
encryptSmall :: PublicKey -> ByteString -> IO (Either RSAError ByteString)
encryptSmall (PublicKey pub) message =
    RSA.OAEP.encrypt (RSA.OAEP.defaultOAEPParams Hash.SHA512) pub message

-- | Decrypt a 'ByteString' of length less than or equal to the 'KeySize'. Skips
-- the symmetric encryption step. For the most part, this should be avoided, but
-- there is no reason not to expose it.
decryptSmall :: PrivateKey -> ByteString -> IO (Either RSAError ByteString)
decryptSmall (PrivateKey priv) message =
    RSA.OAEP.decryptSafer (RSA.OAEP.defaultOAEPParams Hash.SHA512) priv message

-- | A key for symmetric (AEP) encryption
newtype Key = Key { keyBytes :: ByteString }
 deriving (Eq, Ord, Show, Read, Generic, Binary)

-- | Generate a new 'Key'
generateKey :: IO Key
generateKey = generateKeyOfSize 32

-- | Generates a new 'Key' with the given size
generateKeyOfSize :: Int -> IO Key
generateKeyOfSize n =
  Key <$> Random.getRandomBytes n

data SymEncryptionException = SymEncryptionException'CryptoniteError CryptoError
  deriving Show

instance Exception SymEncryptionException

-- | Encrypt a 'ByteString' such that anyone else who has the 'Key' can
-- 'decryptSym' it later.
encryptSym :: Key -> ByteString -> Either SymEncryptionException ByteString
encryptSym key bs =
  case Cipher.cipherInit (keyBytes key) of
    Error.CryptoFailed e -> Left (SymEncryptionException'CryptoniteError e)
    Error.CryptoPassed (c :: AES.AES256) -> Right $ Cipher.ecbEncrypt c paddedMessage
  where
    paddingSize =
      16 - (ByteString.length bs + 1) `mod` 16
    paddedMessage =
      ByteString.concat
        [ ByteString.singleton (fromIntegral paddingSize)
        , ByteString.replicate paddingSize 0
        , bs
        ]

data CroptyError =
    NotEncryptedByCropty
  deriving Show

instance Exception CroptyError

data SymDecryptionException = SymDecryptionException'CryptoniteError CryptoError | SymDecryptionException'CroptyError CroptyError
  deriving Show

instance Exception SymDecryptionException

-- | Decrypt a 'ByteString' which has been 'encryptSym'ed with the given 'Key'.
decryptSym :: Key -> ByteString -> Either SymDecryptionException ByteString
decryptSym key bs =
  case Cipher.cipherInit (keyBytes key) of
    Error.CryptoFailed e -> Left (SymDecryptionException'CryptoniteError e)
    Error.CryptoPassed (c :: AES.AES256) -> do
      let decryptedBytes = Cipher.ecbDecrypt c bs
      if ByteString.length decryptedBytes > 0 then
        let paddingSize = fromIntegral (ByteString.index decryptedBytes 0)
        in Right $ snd (ByteString.splitAt (paddingSize + 1) decryptedBytes)
      else Left $ SymDecryptionException'CroptyError NotEncryptedByCropty

-- | An message 'encrypt'ed for a specific 'PublicKey'. Contains
-- an 'encryptSmall'ed AEP key which only the owner of the corresponding
-- 'PrivateKey' can unlock, and a symmetrically encrypted message
-- for them to decrypt once they 'decryptSmall' their AEP key.
data Message = Message
  { encryptedKey :: ByteString
  , encryptedBytes :: ByteString
  } deriving (Show, Read, Generic, Binary)

-- | The sort of exception we might get during encryption.
data EncryptionException = EncryptionException RSAError
  deriving Show

instance Exception EncryptionException

-- | Encrypt a 'ByteString' for the given 'PublicKey', storing
-- the results into a 'Message'.
encrypt :: PublicKey -> ByteString -> IO Message
encrypt publicKey message = do
  key <- generateKey
  encryptSmall publicKey (keyBytes key) >>= \case
    Left rsaError -> throwIO $ EncryptionException rsaError
    Right encryptedKey -> Message encryptedKey <$> either throwIO pure (encryptSym key message) 

-- | The sort of exception we might get during decryption.
data DecryptionException = DecryptionException RSAError
  deriving Show

instance Exception DecryptionException

-- | Decrypt a 'Message' into a 'ByteString', the original message.
decrypt :: PrivateKey -> Message -> IO ByteString
decrypt privateKey Message{encryptedKey, encryptedBytes} = do
  decryptSmall privateKey encryptedKey >>= \case
    Left rsaError -> throwIO $ DecryptionException rsaError
    Right decryptedKey -> either throwIO pure (decryptSym (Key decryptedKey) encryptedBytes)

-- | The sort of exception we might get during signature.
data SignatureException = SignatureException RSAError
  deriving Show

instance Exception SignatureException

-- | The result of 'sign'ing a 'ByteString'. View this as a digital improvement
-- on the written signature: if you sign something with your 'PrivateKey',
-- anyone with your 'PublicKey' can verify that signature's legitimacy.
newtype Signature = Signature
  { signatureBytes :: ByteString
  } deriving (Eq, Ord, Show, Read, Generic, Binary)

-- | Sign a message with your private key, producing a 'ByteString' that
-- others cannot fabricate for new messages.
sign :: PrivateKey -> ByteString -> IO Signature
sign (PrivateKey privateKey) bs =
    RSA.PSS.signSafer
      (RSA.PSS.defaultPSSParams Hash.SHA512)
      privateKey
      bs
    >>= either (throwIO . SignatureException) (pure . Signature)

-- | Verify the signature of a message.
verify :: PublicKey -> ByteString -> Signature -> Bool
verify (PublicKey pubKey) bs (Signature sig) =
    RSA.PSS.verify (RSA.PSS.defaultPSSParams Hash.SHA512) pubKey bs sig

-- | A convenient type in which to wrap signed things.
data Signed a = Signed
  { signed :: a
  , signedEncoded :: ByteString
  , signature :: Signature
  , signedBy :: PublicKey
  } deriving (Eq, Ord, Show, Read, Generic, Binary)

mkSigned :: Binary a => PrivateKey -> a -> IO (Signed a)
mkSigned privateKey signed = do
  let signedEncoded = LBS.toStrict $ encode signed
  signature <- sign privateKey signedEncoded
  let signedBy = privateToPublic privateKey
  pure $ Signed { signed, signedEncoded, signature, signedBy }
  
verifySigned :: Signed a -> Bool
verifySigned s = verify (signedBy s) (signedEncoded s) (signature s)
