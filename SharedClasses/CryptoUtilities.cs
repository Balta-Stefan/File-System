using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using System.Text;
using Org.BouncyCastle.OpenSsl;
using System.IO;
using Org.BouncyCastle.Crypto.Signers;
using System;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;

namespace SharedClasses
{
    public class CryptoUtilities
    {
        public enum integrityHashAlgorithm { SHA2_256, SHA2_512, SHA3_256, BLAKE2b_512 }
        public enum encryptionAlgorithms { AES, ChaCha, ThreeFish };

        public static readonly int defaultSymmetricKeySize = 32; // 256 bits

        private static SecureRandom random = new SecureRandom();

        public static Pkcs10CertificationRequest generateCSR(AsymmetricCipherKeyPair keyPair, string commonName, string organizationName, string organizationUnit, string state, string country)
        {
            string subjectName = "CN=" + commonName + ", O=" + organizationName + ", OU=" + organizationUnit + ", ST=" + state + ", C=" + country;
            X509Name subject = new X509Name(subjectName);
            Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest("SHA1WITHRSA", subject, keyPair.Public, null, keyPair.Private); // this requires a private key which will be used to sign the request.
                                                                                                                                            //https://stackoverflow.com/questions/2953088/create-a-csr-in-c-sharp-using-an-explicit-rsa-key-pair

            return csr;
        }

        public static X509Certificate sign_CSR(Pkcs10CertificationRequest csr, AsymmetricCipherKeyPair CAKeyPair, BigInteger serialNumber, string signerDN, DateTime notBefore, DateTime notAfter)
        {
            // https://gist.github.com/yutopio/a217a4af63cf6bcf0a530c14c074cf8f

            ISignatureFactory factory = new Asn1SignatureFactory("SHA256WITHRSA", CAKeyPair.Private);

            X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();

            string subjectDN = csr.GetCertificationRequestInfo().Subject.ToString(); // specified in format: CN=commonName, O=organizationName, OU=organizationUnit, ST=state, C=country;

            certGenerator.SetIssuerDN(new X509Name(signerDN));
            certGenerator.SetSubjectDN(new X509Name(subjectDN));
            certGenerator.SetSerialNumber(BigInteger.Arbitrary(64));
            certGenerator.SetNotAfter(notAfter);
            certGenerator.SetNotBefore(notBefore);
            certGenerator.SetPublicKey(csr.GetPublicKey());

            return certGenerator.Generate(factory);
        }
        public static AsymmetricCipherKeyPair generate_RSA_key_pair(int numOfBits)
        {
            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(random, numOfBits));

            return generator.GenerateKeyPair();
        }

        public static AsymmetricCipherKeyPair load_keypair_from_file(string filename)
        {
            AsymmetricCipherKeyPair keyPair = null;

            using (StreamReader stream = System.IO.File.OpenText(filename))
            {
                PemReader pemReader = new PemReader(stream);
                try
                {
                    keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                }
                catch (Exception) { }
            }

            return keyPair;
        }

        /// <summary>
        /// Encrypt/decrypt data using RSA OAEP.Will throw an exception if incorrect key is used or if given digest algorithm doesn't match in decryption mode.The default digest is used (SHA1).
        /// </summary>
        /// <param name="encrypt">True for encryption, false for decryption.</param>
        public static byte[] RSAOAEP(bool encrypt, AsymmetricKeyParameter key, byte[] dataToEncrypt)
        {
            var encrypter = new OaepEncoding(new RsaEngine());
            encrypter.Init(encrypt, key);

            byte[] processedData = encrypter.ProcessBlock(dataToEncrypt, 0, dataToEncrypt.Length);

            return processedData;
        }
        public static int getIVlength(encryptionAlgorithms algorithm)
        {
            switch (algorithm)
            {
                case encryptionAlgorithms.AES:
                    return 16;
                case encryptionAlgorithms.ChaCha:
                    return 8;
                case encryptionAlgorithms.ThreeFish:
                    return 32;
                default: throw new Exception("No such type");
            }
        }


        /// <summary>
        /// Given data will be hashed using the given hashing algorithm, and signed with PSS algorithm using the given key pair.
        /// </summary>
        /// <param name="signature">Contains the signature when verifying.When making a signature, it will be dumped here.</param>
        /// <param name="signVerify">True for signing, false for verifying.</param>
        /// <param name="data">Data to be signed.</param>
        /// <returns>Flag that specifies if the given key and data were indeed used to form the signature if verification is needed.True is returned when making a signature.</returns>
        public static bool signVerify(ref byte[] signature, bool signVerify, byte[] data, AsymmetricKeyParameter key, integrityHashAlgorithm hashingAlgorithm)
        {
            IDigest hashAlgo;

            switch (hashingAlgorithm)
            {
                case integrityHashAlgorithm.SHA2_256:
                    hashAlgo = new Sha256Digest();
                    break;
                case integrityHashAlgorithm.SHA2_512:
                    hashAlgo = new Sha512Digest();
                    break;
                case integrityHashAlgorithm.SHA3_256:
                    hashAlgo = new Sha3Digest();
                    break;
                case integrityHashAlgorithm.BLAKE2b_512:
                    hashAlgo = new Blake2bDigest();
                    break;

                default: return false;
            }

            PssSigner signer = new PssSigner(new RsaEngine(), hashAlgo); // add support for ECC in the future.

            signer.BlockUpdate(data, 0, data.Length);


            signer.Init(signVerify, key);

            if (signVerify == true) // sign
            {
                signature = signer.GenerateSignature();
                return true;
            }
            else // verify
                return signer.VerifySignature(signature);
        }

        public static byte[] ReadFile(string fileName)
        {
            FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read);
            int size = (int)f.Length;
            byte[] data = new byte[size];
            size = f.Read(data, 0, size);
            f.Close();
            return data;
        }

        public static void getRandomData(byte[] toFill)
        {
            random.NextBytes(toFill);
        }

        /// <summary>
        /// IV must be 128 bits long (16 bytes).
        /// </summary>
        /// <param name="key">Key must be 128, 192 or 256 bits long.</param>
        /// <param name="encrypt">Encrypt for true, decrypt for false.</param>
        /// <param name="IV">Must be 16 bytes long.</param>
        /// <returns>Encrypted data</returns>
        public static byte[] encryptDecryptAES(bool encrypt, byte[] data, byte[] key, byte[] IV)
        {
            AesEngine engine = new AesEngine();
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

        /// <summary>
        /// Block size is 256 bits.
        /// </summary>
        /// <param name="IV">Must be 32 bytes long.</param>
        /// <returns></returns>
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

        public static byte[] encryptor(encryptionAlgorithms encryptionAlgorithm, byte[] data, byte[] key, ref byte[] IV, bool encrypt)
        {
            switch (encryptionAlgorithm)
            {
                case encryptionAlgorithms.AES:
                    if (encrypt == true)
                    {
                        IV = new byte[16];
                        getRandomData(IV);
                    }
                    return encryptDecryptAES(encrypt, data, key, IV);
                case encryptionAlgorithms.ChaCha:
                    if (encrypt == true)
                    {
                        IV = new byte[8];
                        getRandomData(IV);
                    }
                    return encryptDecryptChaCha(encrypt, data, key, IV);
                case encryptionAlgorithms.ThreeFish:
                    if (encrypt == true)
                    {
                        IV = new byte[32];
                        getRandomData(IV);
                    }
                    return encryptDecryptThreeFish(encrypt, data, key, IV);

                default: return null;
            }
        }
        private static byte[] hasher(byte[] data, IDigest hashFunction, byte[] salt = null)
        {
            byte[] hashed = new byte[hashFunction.GetDigestSize()];

            if (salt != null)
                hashFunction.BlockUpdate(salt, 0, salt.Length);
            hashFunction.BlockUpdate(data, 0, data.Length);
            hashFunction.DoFinal(hashed, 0);

            return hashed;
        }

        public static byte[] hash(integrityHashAlgorithm hashAlgorithm, byte[] data, byte[] salt = null)
        {
            switch (hashAlgorithm)
            {
                case integrityHashAlgorithm.SHA2_256:
                    return hasher(data, new Sha256Digest());
                case integrityHashAlgorithm.SHA2_512:
                    return hasher(data, new Sha512Digest());
                case integrityHashAlgorithm.SHA3_256:
                    return hasher(data, new Sha3Digest());
                case integrityHashAlgorithm.BLAKE2b_512:
                    return hasher(data, new Blake2bDigest());

                default: return null;
            }
        }



        public static void dumpToPEM(object toDump, string fileName)
        {
            StringBuilder CSRPem = new StringBuilder();
            PemWriter CSRPemWriter = new PemWriter(new StringWriter(CSRPem));
            CSRPemWriter.WriteObject(toDump);
            CSRPemWriter.Writer.Flush();

            string CSRtext = CSRPem.ToString();

            using (StreamWriter f = new StreamWriter(fileName))
            {
                f.Write(CSRtext);
            }
        }
        public static byte[] scryptKeyDerivation(byte[] data, byte[] salt, int derivedKeyLength)
        {
            int iterationCount = 16384; // must be a power of two
            int blockSize = 8;
            int paralelismFactor = 1; // number of threads used?

            return SCrypt.Generate(data, salt, iterationCount, blockSize, paralelismFactor, derivedKeyLength);
        }


        // not used
        public static byte[] SHA2_256_hasher(byte[] data, byte[] salt)
        {
            Sha256Digest hashFunction = new Sha256Digest();
            return hasher(data, hashFunction, salt);
        }

        public static byte[] SHA2_512_hasher(byte[] data, byte[] salt)
        {
            Sha512Digest hashFunction = new Sha512Digest();
            return hasher(data, hashFunction, salt);
        }

        public static byte[] SHA3_256_hasher(byte[] data, byte[] salt)
        {
            Sha3Digest hashFunction = new Sha3Digest();
            return hasher(data, hashFunction, salt);
        }

        public static byte[] Blake2b_hasher(byte[] data, byte[] salt) //512 bit hash
        {
            Blake2bDigest hashFunction = new Blake2bDigest();
            return hasher(data, hashFunction, salt);
        }
        public static bool verifyCertificate(string rootCertFilename, string clientCertificateFilename)
        {
            X509Certificate certificate = null;

            var fileStream = System.IO.File.OpenText(clientCertificateFilename);
            PemReader reader = new PemReader(fileStream);
            try
            {
                certificate = (X509Certificate)reader.ReadObject();
            }
            catch (Exception)
            {
                Console.WriteLine("Error reading the given certificate file.");
                fileStream.Close();
                return false;
            }
            fileStream.Close();
            // validate the certificate 

            X509Certificate rootCert = null;
            fileStream = System.IO.File.OpenText(rootCertFilename);
            reader = new PemReader(fileStream);
            try
            {
                rootCert = (X509Certificate)reader.ReadObject();
            }
            catch (Exception)
            {
                Console.WriteLine("Error reading CA certificate.");
                fileStream.Close();
                return false;
            }

            try
            {
                // WARNING: VERIFYING A CERTIFICATE BY ITS OWN PUBLIC KEY WILL STILL PASS
                certificate.Verify(rootCert.GetPublicKey());
            }
            catch (InvalidKeyException)
            {
                Console.WriteLine("Given certificate not signed by certificate authority");
                return false;
            }
            catch (Exception)
            {
                Console.WriteLine("Error verifying the given certificate");
                return false;
            }

            return true;
            /*
            //https://stackoverflow.com/questions/6097671/how-to-verify-x509-cert-without-importing-root-cert

            X509Chain chain = new X509Chain();
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            chain.ChainPolicy.ExtraStore.Add(rootCert);

            bool valid = chain.Build(clientCertificate);


            X509Certificate2 chainRoot = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
            var temp = chainRoot.RawData;

            return valid && rootCert.Equals(chainRoot); //compareByteArrays(rootCert.RawData, temp);*/
        }

    }
}
