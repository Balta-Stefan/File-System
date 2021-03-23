using System;

namespace SharedClasses
{
    [Serializable]
    public class SessionInfo
    {
        public enum status { SUCCESS, FAILURE}
        public status sessionStatus;

        public CryptoUtilities.integrityHashAlgorithm hashingAlgorithm;
        public CryptoUtilities.encryptionAlgorithms encryptionAlgorithm;

        public string message;
        public readonly byte[] serializedRoot;
        public readonly string cookie;
        public readonly byte[] keyDerivationSalt; // IV used to derive key for symmetric encryption of the user's files.This is combined on the client's machine along with his password (Scrypt algorithm is used).
        public byte[] clientCertificate; // contains signed client certificate.Sent as a reply to registration query.

        /// <summary>
        /// Used only on registration as a reply to the client.
        /// </summary>
        public SessionInfo(string message, status sessionStatus, byte[] clientCertificate)
        {
            this.message = message;
            this.sessionStatus = sessionStatus;
            this.clientCertificate = clientCertificate;
        }

        /// <summary>
        /// Used only in unsuccessful logins.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="sessionStatus"></param>
        public SessionInfo(string message, status sessionStatus)
        {
            this.message = message;
            this.sessionStatus = sessionStatus;
        }

        /// <summary>
        /// Used to return login/registration information to the user.
        /// </summary>
        /// <param name="root"></param>
        /// <param name="cookie"></param>
        /// <param name="keyDerivationSalt">Used by the user to derive his symmetric key for file encryption.</param>
        /// <param name="sessionStatus">Indicates whether login/registration is successful.</param>
        /// <param name="hashingAlgorithm">Hashing algorithm chosen by the user.</param>
        /// <param name="encryptionAlgorithm">Symmetric encryption algorithm chosen by the user.</param>
        /// <param name="clientCertificate">Client's certificate returned only after successful registration.</param>
        public SessionInfo(byte[] serializedRoot, string cookie, byte[] keyDerivationSalt, string message, status sessionStatus, CryptoUtilities.integrityHashAlgorithm hashingAlgorithm, CryptoUtilities.encryptionAlgorithms encryptionAlgorithm, byte[] clientCertificate = null)
        {
            this.serializedRoot = serializedRoot; 
            this.cookie = cookie;
            this.keyDerivationSalt = keyDerivationSalt;
            this.message = message;
            this.clientCertificate = clientCertificate;
            this.sessionStatus = sessionStatus;
            this.hashingAlgorithm = hashingAlgorithm;
            this.encryptionAlgorithm = encryptionAlgorithm;
        }
    }
}
