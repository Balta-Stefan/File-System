using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;


namespace CustomFS
{
    public class CryptoUtilities
    {
        private static SecureRandom random = new SecureRandom();
        //private byte[] encryptionKey; //Encryption key will be derived from the user's password.This key will be used for filesystem encryption.
        //private byte[] MAC_key; //MAC key will also be derived form user's password.

        public static void getRandomData(byte[] toFill)
        {
            random.NextBytes(toFill);
        }

        /// <summary>
        /// IV and key must be of equal size.
        /// </summary>
        /// <param name="key">Key must be 128, 192 or 256 bits long.</param>
        /// <param name="encrypt">Encrypt for true, decrypt for false.</param>
        /// <returns>Encrypted data</returns>
        public static byte[] encryptDecryptAES(bool encrypt, byte[] data, byte[] key, byte[] IV)
        {
            IBlockCipher engine = new AesEngine();
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));
            ParametersWithIV allParams = new ParametersWithIV(new KeyParameter(key), IV); //contains IV and the key


            //encrypt
            cipher.Init(encrypt, allParams);
            byte[] cipherText = new byte[cipher.GetOutputSize(data.Length)];

            int outputLen = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            try
            {
                cipher.DoFinal(cipherText, outputLen);
            }
            catch (CryptoException)
            {
                return null;
            }

            return cipherText;
        }


        /// <param name="IV">Must be exactly 8 bytes.</param>
        /// <returns></returns>
        public static byte[] encryptDecryptChaCha(bool encrypt, byte[] data, byte[] key, byte[] IV)
        {
            IStreamCipher engine = new ChaChaEngine();
            BufferedStreamCipher cipher = new BufferedStreamCipher(engine);
            ParametersWithIV allParams = new ParametersWithIV(new KeyParameter(key), IV);

            cipher.Init(encrypt, allParams);
            byte[] workData = new byte[cipher.GetOutputSize(data.Length)];
            int outputLen = cipher.ProcessBytes(data, 0, data.Length, workData, 0);
            try
            {
                cipher.DoFinal(workData, outputLen);
            }
            catch (CryptoException)
            {
                return null;
            }


            return workData;
        }

        public static byte[] encryptDecryptThreeFish(bool encrypt, byte[] data, byte[] key, byte[] IV)
        {
            IBlockCipher engine = new ThreefishEngine(256);
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));
            ParametersWithIV allParams = new ParametersWithIV(new KeyParameter(key), IV); //contains IV and the key


            //encrypt
            cipher.Init(encrypt, allParams);
            byte[] cipherText = new byte[cipher.GetOutputSize(data.Length)];

            int outputLen = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            try
            {
                cipher.DoFinal(cipherText, outputLen);
            }
            catch (CryptoException)
            {
                return null;
            }

            return cipherText;
        }

        private static byte[] hasher(byte[] data, byte[] salt, IDigest hashFunction)
        {
            byte[] hashed = new byte[hashFunction.GetDigestSize()];

            hashFunction.BlockUpdate(salt, 0, salt.Length);
            hashFunction.BlockUpdate(data, 0, data.Length);
            hashFunction.DoFinal(hashed, 0);

            return hashed;
        }

        public static byte[] SHA2_256_hasher(byte[] data, byte[] salt)
        {
            Sha256Digest hashFunction = new Sha256Digest();
            return hasher(data, salt, hashFunction);
        }

        public static byte[] SHA2_512_hasher(byte[] data, byte[] salt)
        {
            Sha512Digest hashFunction = new Sha512Digest();
            return hasher(data, salt, hashFunction);
        }

        public static byte[] SHA3_256_hasher(byte[] data, byte[] salt)
        {
            Sha3Digest hashFunction = new Sha3Digest();
            return hasher(data, salt, hashFunction);
        }

        public static byte[] Blake2b_hasher(byte[] data, byte[] salt) //512 bit hash
        {
            Blake2bDigest hashFunction = new Blake2bDigest();
            return hasher(data, salt, hashFunction);
        }

        public static byte[] scryptKeyDerivation(byte[] data, byte[] salt, int derivedKeyLength)
        {
            //SCrypt.Generate(password, passData.salt, iterationCount, blockSize, paralelismFactor, passData.hashed_password_with_salt.Length);

            int iterationCount = 16384; // must be a power of two
            int blockSize = 8;
            int paralelismFactor = 1; // number of threads used?

            return SCrypt.Generate(data, salt, iterationCount, blockSize, paralelismFactor, derivedKeyLength);
        }
        /*public static byte[] sign_ECDSA(byte[] data, AsymmetricKeyParameter key)
        {

        }*/

        /*public static byte[] derivePassword()
        {

        }*/
    }
}
