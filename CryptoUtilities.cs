using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Digests;


namespace CustomFS
{
    public class CryptoUtilities
    {
        private static SecureRandom random = new SecureRandom();

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
            catch (CryptoException ce)
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
            catch (CryptoException ce)
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
            catch (CryptoException ce)
            {
                return null;
            }

            return cipherText;
        }

        public static byte[] SHA2_256_hasher(byte[] data, byte[] salt)
        {
            Sha256Digest hashFunction = new Sha256Digest();
            byte[] hashed = new byte[hashFunction.GetDigestSize()];

            hashFunction.BlockUpdate(salt, 0, salt.Length);
            hashFunction.BlockUpdate(data, 0, data.Length);
            hashFunction.DoFinal(hashed, 0);

            return hashed;
        }

        public static byte[] SHA2_512_hasher(byte[] data, byte[] salt)
        {
            Sha512Digest hashFunction = new Sha512Digest();
            byte[] hashed = new byte[hashFunction.GetDigestSize()];

            hashFunction.BlockUpdate(salt, 0, salt.Length);
            hashFunction.BlockUpdate(data, 0, data.Length);
            hashFunction.DoFinal(hashed, 0);

            return hashed;
        }

        public static byte[] SHA3_256_hasher(byte[] data, byte[] salt)
        {
            Sha3Digest hashFunction = new Sha3Digest();
            byte[] hashed = new byte[hashFunction.GetDigestSize()];

            hashFunction.BlockUpdate(salt, 0, salt.Length);
            hashFunction.BlockUpdate(data, 0, data.Length);
            hashFunction.DoFinal(hashed, 0);

            return hashed;
        }

    }
}
