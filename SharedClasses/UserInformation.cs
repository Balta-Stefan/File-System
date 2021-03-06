﻿using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SharedClasses.CryptoUtilities;

namespace SharedClasses
{
    [Serializable]
    public class UserInformation
    {
        public readonly byte[] passwordStorageSalt = new byte[16]; // arbitrarily chosen salt size
        public readonly byte[] symmetricEncryptionKeyDerivationSalt; // this is the salt used to derive the symmetric key which will be used by the user to encrypt his files.
        public readonly byte[] hashed_password_with_salt = null;
        public readonly integrityHashAlgorithm hashingAlgorithm = integrityHashAlgorithm.SHA3_256;
        public readonly encryptionAlgorithms encryptionAlgorithm = encryptionAlgorithms.AES;
        private byte[] encodedCertificate;
        public readonly string userName;
        [NonSerialized] private readonly X509Certificate userCertificate;

        public static readonly int hashSize = 32; // 256 bits   
        public static readonly short keySize = 32; // 256 bit key size will be used for all algorithms

        public byte[] userRoot;
        public UserInformation(string userName, byte[] userRoot, byte[] password, integrityHashAlgorithm hashingAlgorithm, encryptionAlgorithms encryptionAlgorithm, byte[] symmetricEncryptionKeyDerivationSalt, X509Certificate userCertificate)
        {
            this.userName = userName;
            this.userRoot = userRoot;
            this.hashingAlgorithm = hashingAlgorithm;
            this.encryptionAlgorithm = encryptionAlgorithm;
            this.symmetricEncryptionKeyDerivationSalt = symmetricEncryptionKeyDerivationSalt;
            encodedCertificate = userCertificate.GetEncoded();
            // generate a salt
            CryptoUtilities.getRandomData(passwordStorageSalt);
            // pass the password and salt through Scrypt key derivation function
            hashed_password_with_salt = CryptoUtilities.scryptKeyDerivation(password, passwordStorageSalt, hashSize);
        }

        public X509Certificate decodeCertificate()
        {
            return new X509CertificateParser().ReadCertificate(encodedCertificate);
        }

        public override string ToString()
        {
            string saltStr = string.Empty;
            string passwordHash = string.Empty;

            foreach (byte b in passwordStorageSalt)
                saltStr += (char)b;
            foreach (byte b in hashed_password_with_salt)
                passwordHash += (char)b;

            return "Salt: " + saltStr + "\nPassword hash: " + passwordHash + "\nIntegrity: " + hashingAlgorithm + "\nEncryption algorithm: " + encryptionAlgorithm;
        }

    }

}
