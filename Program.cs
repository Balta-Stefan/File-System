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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace CustomFS
{
    enum hashAlgorithm { first, second};
    class hashedPassword
    {
        public hashedPassword(byte[] password, integrityHashAlgorithm hashingAlgorithm)
        {
            this.hashingAlgorithm = hashingAlgorithm;
            // generate a salt
            CryptoUtilities.getRandomData(salt);
            // pass the password and salt through Scrypt key derivation function
            hashed_password_with_salt = CryptoUtilities.scryptKeyDerivation(password, salt, hashSize);
        }

        public readonly byte[] salt = new byte[16]; // arbitrary salt size
        public readonly byte[] hashed_password_with_salt = null;
        public readonly integrityHashAlgorithm hashingAlgorithm = integrityHashAlgorithm.SHA3_256;

        public static readonly int hashSize = 32; // 256 bits
        public enum integrityHashAlgorithm { SHA2_256, SHA2_512, SHA3_256, BLAKE2b_512}
    }
    class Program
    {
        private string userDatabaseFilename = "User database.bin";
        private Dictionary<string, hashedPassword> database = null;

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
                    passwordLength--;
                    Console.Write("\b \b");
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
            bool returnValue = false;
            Console.WriteLine("Username:");
            string username = Console.ReadLine();
            byte[] password = inputPassword();

            hashedPassword passData;

            // check the database
            if (database.TryGetValue(username, out passData))
            {
                byte[] passwordHash = CryptoUtilities.scryptKeyDerivation(password, passData.salt, passData.hashed_password_with_salt.Length);

                // check if the two derived keys are equal
                returnValue = compareByteArrays(password, passwordHash);
            }

            // delete the password
            for (int i = 0; i < password.Length; i++)
                password[i] = 0;
            password = null;

            return returnValue;
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

            hashedPassword.integrityHashAlgorithm hashAlgorithm = hashedPassword.integrityHashAlgorithm.SHA3_256;
            string[] enumValues = Enum.GetNames(typeof(hashedPassword.integrityHashAlgorithm));
            int counter = 1;

            foreach(string s in enumValues)
            {
                Console.WriteLine(counter++ + ")" + s);
            }

            Console.WriteLine("Which hashing algorithm to use for file integrity validation?");
            while(true)
            {
                string input = Console.ReadLine();
                try
                {
                    int number = Int32.Parse(input);
                    if (number > 0 && number <= enumValues.Length) // indexes start from 1 (that's why counter is initialized to 1)
                    {
                        hashAlgorithm = (hashedPassword.integrityHashAlgorithm)Enum.Parse(typeof(hashedPassword.integrityHashAlgorithm), enumValues[number - 1]);
                        break;
                    }
                    else
                        Console.WriteLine("No such index!");
                }catch(FormatException)
                {
                    Console.WriteLine("Incorrect input!");
                }
            } 

            hashedPassword passwordData = new hashedPassword(pass, hashAlgorithm);
          
            // delete the password
            for (int i = 0; i < pass.Length; i++)
                pass[i] = 0;
            pass = null;


            // handle the digital certificate
                // the user supplies a filename that contains an RSA public key.The rest will be entered manually.That certificate has to be signed programatically.
                // in the future, add support for eliptic curve cryptography
                // to do


            // ask the user which hashing algorithm shall be used for file integrity
            


            // do after successfully performing a registration
            serializeUserDatabase();
        }

        private void serializeUserDatabase()
        {
            // to do
        }
        private void deserializeDatabase() // call on program startup
        {
            // deserialize the database

            Stream stream = null;
            try
            {
                IFormatter formatter = new BinaryFormatter();
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
            obj.deserializeDatabase(); // call on startup every time
            obj.inputPassword();

            
        

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
