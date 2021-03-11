using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using DokanNet;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using static CustomFS.CryptoUtilities;

namespace CustomFS
{
    enum hashAlgorithm { first, second};

    [Serializable]
    class hashedPassword
    {
        public readonly byte[] salt = new byte[16]; // arbitrarily chosen salt size
        public readonly byte[] hashed_password_with_salt = null;
        public readonly byte[] encryptionKeyIV; // used in key derivation
        public readonly integrityHashAlgorithm hashingAlgorithm = integrityHashAlgorithm.SHA3_256;
        public readonly encryptionAlgorithms encryptionAlgorithm = encryptionAlgorithms.AES;

        public static readonly int hashSize = 32; // 256 bits   
        public static readonly short keySize = 32; // 256 bit key size will be used for all algorithms

        public hashedPassword(byte[] password, integrityHashAlgorithm hashingAlgorithm, encryptionAlgorithms encryptionAlgorithm)
        {
            this.hashingAlgorithm = hashingAlgorithm;
            this.encryptionAlgorithm = encryptionAlgorithm;
            // generate a salt
            CryptoUtilities.getRandomData(salt);
            // pass the password and salt through Scrypt key derivation function
            hashed_password_with_salt = CryptoUtilities.scryptKeyDerivation(password, salt, hashSize);

            encryptionKeyIV = new byte[16];
            CryptoUtilities.getRandomData(encryptionKeyIV);
        }

        public override string ToString()
        {
            string saltStr = string.Empty;
            string passwordHash = string.Empty;

            foreach (byte b in salt)
                saltStr += (char)b;
            foreach (byte b in hashed_password_with_salt)
                passwordHash += (char)b;

            return "Salt: " + saltStr + "\nPassword hash: " + passwordHash + "\nIntegrity: " + hashingAlgorithm + "\nEncryption algorithm: " + encryptionAlgorithm;
        }

    }
    class Program
    {
        private string userDatabaseFilename = "User database.bin";
        private Dictionary<string, hashedPassword> database = null;

        private byte[] encryptionKey;

        private static readonly string CAfile = "CA.pem";

        byte[] inputPassword()
        {
            // Instantiate the secure string.
            ConsoleKeyInfo key;
            byte[] temporaryPassword = new byte[15];
            int passwordLength = 0;
            

            Console.Write("Enter password: ");
            do
            {
                key = Console.ReadKey(true);
                // Ignore any key out of alphanumeric range.

                if((int)key.Key == 8) // backspace
                {
                    if(passwordLength > 0)
                    {
                        passwordLength--;
                        Console.Write("\b \b");
                    }
                }
                else if (((int)key.Key) >= 32 && ((int)key.Key <= 126))
                {
                    // Append the character to the password.
                    temporaryPassword[passwordLength++] = (byte)key.KeyChar;
                    Console.Write("*");
                    if(passwordLength == temporaryPassword.Length)
                    {
                        // reallocate the array
                        byte[] tempPass = new byte[passwordLength * 2];
                        for(int i = 0; i < passwordLength; i++)
                        {
                            // zero out the old password
                            tempPass[i] = temporaryPassword[i];
                            temporaryPassword[i] = 0;
                        }
                        temporaryPassword = tempPass;
                    }
                }
                // Exit if Enter key is pressed.
            } while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();
            Array.Resize(ref temporaryPassword, passwordLength);

            return temporaryPassword;
        }

        public bool login()
        {
            Console.WriteLine("Username:");
            string username = Console.ReadLine();
            byte[] password = inputPassword();

            hashedPassword passData;

            // check the database
            if (database.TryGetValue(username, out passData) == true)
            {
                byte[] passwordHash = CryptoUtilities.scryptKeyDerivation(password, passData.salt, passData.hashed_password_with_salt.Length);

                // check if the two derived keys are equal
                if (compareByteArrays(passwordHash, passData.hashed_password_with_salt) == false)
                    return false;
            }
            else
                return false;

            encryptionKey = scryptKeyDerivation(password, passData.encryptionKeyIV, hashedPassword.keySize); // derive the key for encryption 

            Array.Clear(password, 0, password.Length);

            // handle the client certificate

            Console.WriteLine("Input the name of the certificate in PEM format:");
            string certFilename = Console.ReadLine();

            if(certFilename.Equals(CAfile))
            {
                Console.WriteLine("Can't use CA's own certificate!");
                return false;
            }

            // check if the file exists
            if (System.IO.File.Exists(certFilename) == false)
            {
                Console.WriteLine("Given file doesn't exist.Put it into the directory where exe is located");
                return false;
            }
            else
            {
                X509Certificate certificate = null;

                var fileStream = System.IO.File.OpenText(certFilename);
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

                // validate the certificate 

                X509Certificate rootCert = null;
                fileStream = System.IO.File.OpenText(CAfile);
                reader = new PemReader(fileStream);
                try
                {
                    rootCert = (X509Certificate)reader.ReadObject();
                }
                catch(Exception)
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
                catch(InvalidKeyException)
                {
                    Console.WriteLine("Given certificate not signed by certificate authority");
                    return false;
                }
                catch(Exception)
                {
                    Console.WriteLine("Error verifying the given certificate");
                    return false;
                }

                //Console.WriteLine(certificate);
            }

            return true;
        }
        /// <summary>
        /// Takes an array of values and asks the user to choose one.
        /// </summary>
        /// <param name="enumValues"></param>
        /// <returns>Index of the chosen value</returns>
        private int chooseAlgorithm(string[] enumValues)
        {
            int counter = 1;

            foreach (string s in enumValues)
            {
                Console.WriteLine(counter++ + ")" + s);
            }

            Console.WriteLine("Which hashing algorithm to use for file integrity validation?");
            while (true)
            {
                string input = Console.ReadLine();
                try
                {
                    int number = Int32.Parse(input);
                    if (number > 0 && number <= enumValues.Length) // indexes start from 1 (that's why counter is initialized to 1)
                    {
                        return number - 1;
                    }
                    else
                        Console.WriteLine("No such index!");
                }
                catch (FormatException)
                {
                    Console.WriteLine("Incorrect input!");
                }
            }
        }
        public void registerUser()
        {
            string userName;
            byte[] pass;

            while(true)
            {
                Console.WriteLine("Enter username: ");
                userName = Console.ReadLine();
                if (database.ContainsKey(userName) == true)
                {
                    Console.WriteLine("Such username already exists!");
                    Console.WriteLine("");
                }
                else
                    break;
            }

            while(true)
            {
                byte[] firstPasswordInput = inputPassword();
                Console.WriteLine("Reenter your password: ");
                byte[] secondPasswordInput = inputPassword();

                if (compareByteArrays(firstPasswordInput, secondPasswordInput) == false)
                    Console.WriteLine("Given passwords don't match");
                else
                {
                    pass = firstPasswordInput;
                    break;
                }
            }

            string[] hashEnumValues = Enum.GetNames(typeof(integrityHashAlgorithm));
            integrityHashAlgorithm hashAlgorithm = (integrityHashAlgorithm)Enum.Parse(typeof(integrityHashAlgorithm), hashEnumValues[chooseAlgorithm(hashEnumValues)]);

            string[] encryptionAlgorithmsEnumValues = Enum.GetNames(typeof(encryptionAlgorithms));
            encryptionAlgorithms encryptionAlgorithm = (encryptionAlgorithms)Enum.Parse(typeof(encryptionAlgorithms), encryptionAlgorithmsEnumValues[chooseAlgorithm(encryptionAlgorithmsEnumValues)]);
            
            hashedPassword passwordData = new hashedPassword(pass, hashAlgorithm, encryptionAlgorithm);
         

            // delete the password
            for (int i = 0; i < pass.Length; i++)
                pass[i] = 0;
            pass = null;


            // create the digital certificate
            // The user must supply a filename that contains his private key in PEM format.
            // in the future, add support for eliptic curve cryptography.

            AsymmetricCipherKeyPair privateKey = null;
            // obtain the key file
            while (true)
            {
                Console.WriteLine("Enter the name of the file that contains RSA private key in PEM format.");
                string privateKeyFilename = Console.ReadLine();

                // check if the file exists
                if (System.IO.File.Exists(privateKeyFilename) == false)
                {
                    Console.WriteLine("Given file doesn't exist.Put it into the directory where exe is located");
                    continue;
                }

                // handle the private key
                var fileStream = System.IO.File.OpenText(privateKeyFilename);
                PemReader reader = new PemReader(fileStream);
                try
                {
                    privateKey = (AsymmetricCipherKeyPair)reader.ReadObject();
                }
                catch(Exception)
                {
                    Console.WriteLine("Error reading the given private key.");
                    continue;
                }
                fileStream.Close();
                
                /*if(privateKey is RsaKeyParameters == false)
                {
                    Console.WriteLine("Given key isn't an RSA key");
                    continue;
                }*/
                // what happens if the user supplies a public RSA key, instead of the private one?
                // to do
                break;
            }

            //var publicKey = new RsaKeyParameters(false, ((RsaPrivateCrtKeyParameters)privateKey).Modulus, ((RsaPrivateCrtKeyParameters)privateKey).PublicExponent);
            //AsymmetricCipherKeyPair keyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);

            // create the certificate request using the keys.The request will be manually signed on the back end.
            Console.WriteLine("Enter common name: ");
            string commonName = Console.ReadLine();
            Console.WriteLine("Enter organization name: ");
            string organizationName = Console.ReadLine();
            Console.WriteLine("Enter organization unit: ");
            string organizationUnit = Console.ReadLine();
            Console.WriteLine("Enter state: ");
            string state = Console.ReadLine();
            Console.WriteLine("Enter country: ");
            string country = Console.ReadLine();

            CryptoUtilities.generateCSR(privateKey, commonName, organizationName, organizationUnit, state, country);

            // do after successfully performing a registration
           
            database.Add(userName, passwordData);
            serializeUserDatabase();
        }

        private void serializeUserDatabase()
        {
            try
            {
                System.IO.Stream ms = System.IO.File.OpenWrite(userDatabaseFilename);

                BinaryFormatter formatter = new BinaryFormatter();
                //It serialize the employee object  
                formatter.Serialize(ms, database);
                ms.Flush();
                ms.Close();
                ms.Dispose();
            }
           catch(Exception e)
            {
                Console.WriteLine("Error during user database serialization" + e);
            }
        }
        private void deserializeDatabase() // call on program startup
        {
            // deserialize the database

            Stream stream = null;
            try
            {
                BinaryFormatter formatter = new BinaryFormatter();
                stream = new FileStream(userDatabaseFilename, System.IO.FileMode.Open, System.IO.FileAccess.Read, FileShare.Read);
                database = (Dictionary<string, hashedPassword>)formatter.Deserialize(stream);
                stream.Close();
            }
            catch (System.IO.FileNotFoundException)
            {
                if (stream != null)
                    stream.Close();

                // create the database
                database = new Dictionary<string, hashedPassword>();
            }
        }



        private bool compareByteArrays(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
                return false;
            else if ((first == null && second != null) || (first != null && second == null))
                return false;
            else if(first != null && second != null)
            {
                for(int i = 0; i < first.Length; i++)
                {
                    if (first[i] != second[i])
                        return false;
                }
            }
            return true;
        }
        
 
        static void Main(string[] args)
        {
            Program obj = new Program();
            //obj.deserializeDatabase(); // call on startup every time

            //obj.registerUser();
            //obj.login();



            int a = 3;
            /*
            byte[] data = Encoding.UTF8.GetBytes("my longest message that will be entered in this example");
            byte[] key = Encoding.UTF8.GetBytes("a key that unlocks doors will 12");
            byte[] IV = new byte[8];
            CryptoUtilities.getRandomData(IV);

            byte[] cipherText = CryptoUtilities.encryptDecryptChaCha(true, data, key, IV);
            byte[] deciphered = CryptoUtilities.encryptDecryptChaCha(true, cipherText, key, IV);
            Console.WriteLine(Encoding.UTF8.GetString(cipherText));
            Console.WriteLine(Encoding.UTF8.GetString(deciphered));*/

            /*
            Stream stream = null;
            try
            {
                IFormatter formatter = new BinaryFormatter();
                stream = new FileStream("Filesystem tree.bin", System.IO.FileMode.Open, System.IO.FileAccess.Read, FileShare.Read);
                File obj = (File)formatter.Deserialize(stream);
                stream.Close();
                new CustomFileSystem("Y:", obj).Mount(@"Y:\", DokanOptions.DebugMode | DokanOptions.StderrOutput);

            }
            catch (System.IO.FileNotFoundException exception)
            {
                if(stream != null)
                    stream.Close();
                new CustomFileSystem("Y:").Mount(@"Y:\", DokanOptions.DebugMode | DokanOptions.StderrOutput);
            }*/
        }
    }
}
