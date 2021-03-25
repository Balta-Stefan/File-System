using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharedClasses
{
    [Serializable]
    public class Message
    {
        // types of messages:
        // 1)When user logs in. - must contain: string username, byte[] password, byte[] client certificate (encoded)
        // 2)Login reply. - must contain: File sharedFolder, File userRoot, byte[] keyDerivationSalt, integrity hash algorithm, encryption algorithm
        // 3)Registration. - must contain: File userRoot, byte[] keyDerivationSalt, integrity hash algorithm, encryption algorithm, encoded CSR
        // 4)Registration reply. - must contain byte[] encodedSignedCertificate, string message
        // 5)Logout
        // 6)Logout reply

        public static readonly CryptoUtilities.encryptionAlgorithms messageEncryptionAlgorithm = CryptoUtilities.encryptionAlgorithms.AES;

        public byte[] symmetricKey;
        public byte[] IV;
        public byte[] encryptedData;
        public string message;

        public Message() 
        {
            symmetricKey = new byte[CryptoUtilities.defaultSymmetricKeySize];
        }
        /// <summary>
        /// Use for returning error messages from server.
        /// </summary>
        public Message(string message, AsymmetricKeyParameter serverPrivateKey)
        {
            symmetricKey = new byte[CryptoUtilities.defaultSymmetricKeySize];
            this.message = message;
            encryptedData = CryptoUtilities.serialize_and_encrypt_object(this, ref symmetricKey, ref IV, serverPrivateKey, messageEncryptionAlgorithm);
        }


        /// <summary>
        /// The client will call this with the server's public key.The server will call this with its private key.
        /// </summary>
        public object decrypt(AsymmetricKeyParameter asymmetricKey)
        {
            return CryptoUtilities.deserialize_and_decrypt_object(encryptedData, symmetricKey, IV, asymmetricKey, messageEncryptionAlgorithm);
        }
       
        [Serializable]
        public class ShareFile : Message
        {
            // to do - take care: the sender must serialize the shared directory.This means that his entire file system will be pulled over.Filesystem has to make sure that parentDir reference is set to null before serialization, and reset after.
            public File fileToShare;
            /// <summary>
            /// This ctor will be used by the client to send the new file, and by the server in order to return the updated shared directory to the user.
            /// </summary>
            /// <param name="share"></param>
            /// <param name="asymmetricKey"></param>
            public ShareFile(File share, AsymmetricKeyParameter asymmetricKey)
            { 
                fileToShare = share;
                encryptedData = CryptoUtilities.serialize_and_encrypt_object(this, ref symmetricKey, ref IV, asymmetricKey, messageEncryptionAlgorithm);
            }
        }
        
        [Serializable]
        public class PublicKeyRequest : Message
        {
            private string PEMpublicKey;
            public string userName;
            /// <summary>
            /// Client ctor
            /// </summary>
            public PublicKeyRequest(string userName, AsymmetricKeyParameter serverPublicKey) 
            {
                this.userName = userName;

                encryptedData = CryptoUtilities.serialize_and_encrypt_object(this, ref symmetricKey, ref IV, serverPublicKey, messageEncryptionAlgorithm);
            }
            public PublicKeyRequest(AsymmetricKeyParameter serverPrivateKey, AsymmetricKeyParameter userPublicKey, string message)
            {
                this.message = message;
                if(userPublicKey != null)
                    PEMpublicKey = CryptoUtilities.dumpToPEM(userPublicKey, null);
                encryptedData = CryptoUtilities.serialize_and_encrypt_object(this, ref symmetricKey, ref IV, serverPrivateKey, messageEncryptionAlgorithm);
            }

            public AsymmetricKeyParameter decodePublicKey()
            {
                if (PEMpublicKey == null)
                    return null;
                return (AsymmetricKeyParameter)(CryptoUtilities.readPem(PEMpublicKey));
            }
        }
        

        [Serializable]
        public class Login : Message
        {
            public string username;
            public byte[] password;
            public byte[] encodedClientCertificate;
            public Login(string username, byte[] password, X509Certificate clientCertificate, AsymmetricKeyParameter serverPublicKey)
            {
                this.username = username;
                this.password = password;
                encodedClientCertificate = clientCertificate.GetEncoded();

                // encrypt the contents with the server's public key
                encryptedData = CryptoUtilities.serialize_and_encrypt_object(this, ref symmetricKey, ref IV, serverPublicKey, messageEncryptionAlgorithm);
            }
            public X509Certificate decodeCertificate()
            {
                return new X509CertificateParser().ReadCertificate(encodedClientCertificate);
            }
        }

        [Serializable]
        public class LoginReply : Message
        {
            public byte[] sharedDirectory;
            public byte[] userRoot;
            public byte[] keyDerivationSalt;
            public CryptoUtilities.integrityHashAlgorithm hashAlgorithm;
            public CryptoUtilities.encryptionAlgorithms encryptionAlgorithm;

            public string cookie;
            
            /// <summary>
            /// Use for unsuccessful login.
            /// </summary>
            public LoginReply(string message, AsymmetricKeyParameter serverPrivateKey)
            {
                this.message = message;
                encryptedData = CryptoUtilities.serialize_and_encrypt_object(this, ref symmetricKey, ref IV, serverPrivateKey, encryptionAlgorithm);
            }

            /// <summary>
            /// Use for successful login.
            /// </summary>
            public LoginReply(string cookie, string message, byte[] sharedDirectory, byte[] userRoot, byte[] keyDerivationSalt, AsymmetricKeyParameter serverPrivateKey, CryptoUtilities.integrityHashAlgorithm hashAlgorithm, CryptoUtilities.encryptionAlgorithms encryptionAlgorithm)
            {
                this.cookie = cookie;
                this.message = message;
                this.sharedDirectory = sharedDirectory;
                this.userRoot = userRoot;
                this.keyDerivationSalt = keyDerivationSalt;
                this.hashAlgorithm = hashAlgorithm;
                this.encryptionAlgorithm = encryptionAlgorithm;

                encryptedData = CryptoUtilities.serialize_and_encrypt_object(this, ref symmetricKey, ref IV, serverPrivateKey, encryptionAlgorithm);
            }
        }

        [Serializable]
        public class Registration : Message
        {
            public byte[] userRoot;
            public byte[] keyDerivationSalt;
            public string PEMcsr;
            public CryptoUtilities.integrityHashAlgorithm hashAlgorithm;
            public CryptoUtilities.encryptionAlgorithms encryptionAlgorithm;
            public byte[] password;
            public string username;

            public Registration(string username, byte[] password, Pkcs10CertificationRequest csr, byte[] userRoot, byte[] keyDerivationSalt, AsymmetricKeyParameter serverPublicKey, CryptoUtilities.integrityHashAlgorithm hashAlgorithm, CryptoUtilities.encryptionAlgorithms encryptionAlgorithm)
            {
                this.username = username;
                this.password = password;
                this.userRoot = userRoot;
                this.keyDerivationSalt = keyDerivationSalt;
                this.hashAlgorithm = hashAlgorithm;
                this.encryptionAlgorithm = encryptionAlgorithm;

                // dump csr to PEM string
                PEMcsr = CryptoUtilities.dumpToPEM(csr, null);

                encryptedData = CryptoUtilities.serialize_and_encrypt_object(this, ref symmetricKey, ref IV, serverPublicKey, messageEncryptionAlgorithm);
            }

            public Pkcs10CertificationRequest decodePEMcsr()
            {
                using (StringReader reader = new StringReader(PEMcsr))
                {
                    PemReader pemReader = new PemReader(reader);
                    return (Pkcs10CertificationRequest)pemReader.ReadObject();
                }
            }
        }
        
        [Serializable]
        public class RegistrationReply : Message
        {
            public byte[] encodedSignedCertificate;

            /// <summary>
            /// Use for unsuccessful registration.
            /// </summary>
            public RegistrationReply(string message, AsymmetricKeyParameter serverPrivateKey)
            {
                this.message = message;

                encryptedData = CryptoUtilities.serialize_and_encrypt_object(this, ref symmetricKey, ref IV, serverPrivateKey, messageEncryptionAlgorithm);
            }
            /// <summary>
            /// Use for successful registration;
            /// </summary>
            public RegistrationReply(string message, AsymmetricKeyParameter serverPrivateKey, X509Certificate clientCertificate)
            {
                this.message = message;
                encodedSignedCertificate = clientCertificate.GetEncoded();

                encryptedData = CryptoUtilities.serialize_and_encrypt_object(this, ref symmetricKey, ref IV, serverPrivateKey, messageEncryptionAlgorithm);
            }

            public X509Certificate decodeCertificate()
            {
                return new X509CertificateParser().ReadCertificate(encodedSignedCertificate);
            }
        }
    
        [Serializable]
        public class LogOut : Message
        {
            public byte[] userRoot;
            public byte[] sharedDirectory;
            public string cookie;

            /// <summary>
            /// Use for logout replies (from server).
            /// </summary>
            public LogOut(string message, AsymmetricKeyParameter serverPrivateKey)
            {
                this.message = message;
                encryptedData = CryptoUtilities.serialize_and_encrypt_object(this, ref symmetricKey, ref IV, serverPrivateKey, messageEncryptionAlgorithm);
            }
            /// <summary>
            /// Use to log out (user).
            /// </summary>
            public LogOut(AsymmetricKeyParameter serverPublicKey, byte[] userRoot, byte[] sharedDirectory, string cookie)
            {
                this.userRoot = userRoot;
                this.sharedDirectory = sharedDirectory;
                this.cookie = cookie;

                encryptedData = CryptoUtilities.serialize_and_encrypt_object(this, ref symmetricKey, ref IV, serverPublicKey, messageEncryptionAlgorithm);
            }
        }
    }
}
