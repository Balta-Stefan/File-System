using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using static SharedClasses.CryptoUtilities;
using Org.BouncyCastle.Pkcs;

namespace SharedClasses
{
    /// <summary>
    /// Used when registering or logging in.
    /// </summary>
    [Serializable]
    public class Credentials
    {
        public readonly integrityHashAlgorithm hashingAlgorithm = integrityHashAlgorithm.SHA3_256;
        public readonly encryptionAlgorithms encryptionAlgorithm = encryptionAlgorithms.AES;

        public enum messageType { LOGIN, REGISTER }
        public messageType type;

        public byte[] symmetricKey;
        public byte[] encryptedData; // contains encrypted MemoryStream bytes that, when deserialized, give all the fields below.
        public byte[] IV; // used for (en/de)crypting the encryptedData

        public string username;
        public byte[] password;
        public byte[] encodedClientCertificate; // decode with X509CertificateParser().ReadCertificate(encodedClientCertificate);
        public byte[] serializedRoot;
        [NonSerialized] public Pkcs10CertificationRequest csr;
        [NonSerialized] public AsymmetricKeyParameter serverPublicKey;

        public readonly byte[] keyDerivationSalt;

        public Credentials(string username, byte[] password, X509Certificate clientCertificate, AsymmetricKeyParameter serverPublicKey, messageType type, integrityHashAlgorithm hashingAlgorithm = integrityHashAlgorithm.SHA3_256, encryptionAlgorithms encryptionAlgorithm = encryptionAlgorithms.AES, Pkcs10CertificationRequest csr = null, byte[] keyDerivationSalt = null, byte[] serializedRoot = null)
        {
            // 2 of these are used only during registration
            this.serializedRoot = serializedRoot;
            this.keyDerivationSalt = keyDerivationSalt;

            this.username = username;
            this.password = (byte[])password.Clone();
            this.serverPublicKey = serverPublicKey;
            this.hashingAlgorithm = hashingAlgorithm;
            this.encryptionAlgorithm = encryptionAlgorithm;
            this.type = type;
            this.csr = csr;
            encodedClientCertificate = clientCertificate.GetEncoded();


            byte[] IV = null;

            // generate the symmetric key
            byte[] symKey = new byte[defaultSymmetricKeySize];
            getRandomData(symKey);

            // encrypt the symmetric key with the server's public key
            byte[] encryptedSymmetricKey = RSAOAEP(true, serverPublicKey, symKey);

            // serialize and encrypt the data
            BinaryFormatter bf = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, this);
                ms.Position = 0;
                encryptedData = encryptor(encryptionAlgorithm, ms.ToArray(), symKey, ref IV, true);

                this.IV = IV;
                symmetricKey = (byte[])encryptedSymmetricKey.Clone();

                Array.Clear(symKey, 0, symKey.Length);
            }
        }
        /// <summary>
        /// Method performs decryption and deserialization of the encrypted data.
        /// </summary>
        /// <returns>True for success, false otherwise.</returns>
        public bool deserialize(AsymmetricKeyParameter serverPrivateKey)
        {
            byte[] decryptedKey = null;
            byte[] decryptedData = null;

            try
            {
                // decrypt the symmetric key using private key
                decryptedKey = RSAOAEP(false, serverPrivateKey, symmetricKey);

                // decrypt the data using the previously decrypted symmetric key
                decryptedData = encryptor(encryptionAlgorithm, encryptedData, decryptedKey, ref IV, false);

                BinaryFormatter bf = new BinaryFormatter();

                using (MemoryStream ms = new MemoryStream(decryptedData))
                {
                    Credentials tempCreds = (Credentials)bf.Deserialize(ms);

                    username = tempCreds.username;
                    password = (byte[])tempCreds.password.Clone();
                    encodedClientCertificate = tempCreds.encodedClientCertificate;
                }
            }
            catch (Exception) { return false; }
            finally
            {
                if (decryptedKey != null)
                    Array.Clear(decryptedKey, 0, decryptedKey.Length);
                if (decryptedData != null)
                    Array.Clear(decryptedData, 0, decryptedData.Length);
            }

            return true;
        }

        public X509Certificate decodeClientCertificate()
        {
            return new X509CertificateParser().ReadCertificate(encodedClientCertificate);
        }

        ~Credentials()
        {
            Array.Clear(password, 0, password.Length);
        }
    }
}
