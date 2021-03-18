using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
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

        public byte[] encryptionKey;
        public AsymmetricCipherKeyPair keyPair;
        public integrityHashAlgorithm hashingAlgorithm;
        public encryptionAlgorithms encryptionAlgorithm;
        public Filesystem filesystem;
        public File workingDirectory;

        public File root;
        public readonly List<File> requireEncryption = new List<File>();

        private static readonly string CAfile = "CA.pem";

        byte[] inputPassword()
        {
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

        public void login()
        {
            Console.WriteLine("Username:");
            string username = "Marko";//Console.ReadLine();
            byte[] password = inputPassword();

            hashedPassword passData;

            // check the database
            if (database.TryGetValue(username, out passData) == true)
            {
                byte[] passwordHash = scryptKeyDerivation(password, passData.salt, passData.hashed_password_with_salt.Length);

                // check if the two derived keys are equal
                if (compareByteArrays(passwordHash, passData.hashed_password_with_salt) == false)
                    throw new Exception("Incorrect password");
            }
            else
                throw new Exception("Nonexistant user name.");

            encryptionKey = scryptKeyDerivation(password, passData.encryptionKeyIV, hashedPassword.keySize); // derive the key for encryption 

            Array.Clear(password, 0, password.Length);

            // handle the client certificate

            Console.WriteLine("Input the name of the certificate in PEM format:");
            string certFilename = "mojKlijent.pem";// Console.ReadLine();

            if(certFilename.Equals(CAfile))
                throw new Exception("Can't use CA's own certificate!");
            

            // check if the file exists
            if (System.IO.File.Exists(certFilename) == false)
                throw new Exception("Given file doesn't exist.Put it into the directory where exe is located.");
            
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
                    //Console.WriteLine("Error reading the given certificate file.");
                    throw new Exception("Error reading the given certificate file.");
                }
				finally 
				{
					fileStream.Close();
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
                    //Console.WriteLine("Error reading CA certificate.");
                    throw new Exception("Error reading CA certificate.");
                }
				finally 
				{
					fileStream.Close();
				}
                
                try
                {
                    // WARNING: VERIFYING A CERTIFICATE BY ITS OWN PUBLIC KEY WILL STILL PASS
                    certificate.Verify(rootCert.GetPublicKey());
                }
                catch(InvalidKeyException)
                {
                    //Console.WriteLine("Given certificate not signed by certificate authority");
                    throw new Exception("Given certificate not signed by certificate authority");
                }
                catch(Exception)
                {
                    //Console.WriteLine("Error verifying the given certificate");
                    throw new Exception("Error verifying the given certificate");
                }

                //Console.WriteLine(certificate);
            }

            Console.WriteLine("Enter the name of the file that containts your RSA key pair: ");
            string keypairFile = "clientKey.pem";// Console.ReadLine();
            if (System.IO.File.Exists(keypairFile) == false)
            {
                throw new Exception("Given file doesn't exist.Put it into the directory where exe is located");
            }
            var stream = System.IO.File.OpenText(keypairFile);
            PemReader pemReader = new PemReader(stream);
            try
            {
                keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            }
            catch (Exception)
            {
                stream.Close();
                throw new Exception("Error reading the given keypair file.");
            }
            stream.Close();

            hashingAlgorithm = passData.hashingAlgorithm;
            encryptionAlgorithm = passData.encryptionAlgorithm;
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
        
        public MemoryStream loadFile(string path)
        {
            MemoryStream inMemoryCopy = new MemoryStream();
            using (FileStream fs = System.IO.File.OpenRead(path))
            {
                fs.CopyTo(inMemoryCopy);
            }
            inMemoryCopy.Position = 0;

            return inMemoryCopy;
        }

        public void storeFile(MemoryStream stream, string path)
        {
            using (FileStream file = new FileStream(path, FileMode.Create, System.IO.FileAccess.Write))
                stream.CopyTo(file);
        }

        public MemoryStream byteArrayToStream(byte[] bytes)
        {
            return new MemoryStream(bytes);
        }

        private void openFile(string fileName)
        {
            // check if the file exists in the virtual filesystem
            try
            {
                filesystem.downloadFile(fileName);
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
                return;
            }
            finally
            {
                foreach (string s in filesystem.getMessages())
                    Console.WriteLine(s);
            }

            Process tempProcess = new Process
            {
                StartInfo = new ProcessStartInfo(Filesystem.downloadFolderName + Path.DirectorySeparatorChar + fileName)
                {
                    UseShellExecute = true
                }
            };
            tempProcess.Start();
            tempProcess.WaitForExit();
        }

        public void makeDir(string path)
        {
            try
            {
                filesystem.makeDirectory(path);
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                foreach (string s in filesystem.getMessages())
                    Console.WriteLine(s);
            }

        }
        private void listDir()
        {
            List<File> files = filesystem.listWorkingDirectory();

            foreach (File f in files)
            {
                char fileType = (f.isDir == true) ? 'd' : 'f';
                Console.WriteLine(f);
                //Console.WriteLine("(" + fileType + ") " + f.name + ", " + f.metadata.dateCreated + ", " + f.metadata.data.Length + "B");
            }
        }
       
        private void makeTextFile()
        {
            Console.WriteLine("Enter file name:");
            string fileName = Console.ReadLine();

            Console.WriteLine("Enter the contents:");
            string contents = enterText();//Console.ReadLine();

            try
            {
                filesystem.makeTextFile(fileName, contents);
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
        
        private void editTextFileUtility(char[] charArray, int limit)
        {
            Console.Clear();
            for (int i = 0; i < limit; i++)
            {
                if (charArray[i].ToString().Equals(Environment.NewLine))
                    Console.Write("\r\n");
                else
                    Console.Write(charArray[i]);
            }
        }

        /// <summary>
        /// Method which will be used for text file editing and creation.
        /// </summary>
        /// <param name="textArray">Additional text.</param>
        /// <returns></returns>
        string enterText(char[] textArray = null)
        {
            int limit = 0;
            if (textArray == null)
                textArray = new char[15];
            else
                limit = textArray.Length;
                

            Console.Clear();
            editTextFileUtility(textArray, limit);
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);
                // Ignore any key out of alphanumeric range.

                if (key.Key == ConsoleKey.Backspace) // backspace
                {
                    if (limit > 0)
                    {
                        if (textArray[limit - 1] == '\n' && textArray[limit - 2] == '\r')
                            limit--;
                        limit--;
                        //Console.Write("\b \b");
                        editTextFileUtility(textArray, limit);

                    }
                }
                else if (key.Key == ConsoleKey.Enter || ((int)key.Key) >= 32 && ((int)key.Key <= 126))
                {
                    /*if (key.Key == ConsoleKey.Enter)
                        textArray[limit++] = '\n';
                    else*/
                    if (limit >= textArray.Length - 1)
                    {
                        // reallocate the array
                        char[] tempPass = new char[limit * 2];
                        Array.Copy(textArray, tempPass, textArray.Length);
                        textArray = tempPass;
                    }
                    if (key.Key == ConsoleKey.Enter)
                    {
                        textArray[limit++] = '\r';
                        textArray[limit++] = '\n';
                        Console.Write("\r\n");
                    }
                    else
                    {
                        textArray[limit++] = key.KeyChar;
                        Console.Write(key.KeyChar);
                    }
                }
                // Exit if esc key is pressed.
            } while (key.Key != ConsoleKey.Escape);
            Console.Clear();

            char[] finalArray = new char[limit];
            Array.Copy(textArray, finalArray, limit);

            return new string(finalArray);
        }
        private void editTextFile(string fileName)
        {
            File wantedFile = filesystem.findFile(fileName);
            try
            {
                if(wantedFile == null)
                {
                    Console.WriteLine("Given path doesn't exist.");
                    return;
                }
                if (wantedFile.isDir == true)
                {
                    Console.WriteLine("Given path represents a directory.");
                    return;
                }
                if (wantedFile.name.EndsWith(".txt") == false)
                {
                    Console.WriteLine("Given path doesn't represent a text file.");
                    return;
                }
                filesystem.downloadFile(fileName);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return;
            }
            finally
            {
                foreach (string s in filesystem.getMessages())
                    Console.WriteLine(s);
            }

            
            string text = System.IO.File.ReadAllText(Filesystem.downloadFolderName + Path.DirectorySeparatorChar + fileName);
            char[] textArray = text.ToCharArray();
            int limit = text.Length;

            string str = enterText(textArray);

            // write string to file
            System.IO.File.WriteAllText(Filesystem.downloadFolderName + Path.DirectorySeparatorChar + fileName, str);

            // convert file to MemoryStream
            using (MemoryStream fileStream = loadFile(Filesystem.downloadFolderName + Path.DirectorySeparatorChar + fileName))
            {
                wantedFile.metadata.data = fileStream.ToArray();
                requireEncryption.Add(wantedFile);
                System.IO.File.Delete(Filesystem.downloadFolderName + Path.DirectorySeparatorChar + fileName);
            }
        }
       
        private void move(string arg)
        {
            // arg should contain 2 paths separated by space, each specified between double quotes ("first" "second")

            if(arg.Length < 5)
            {
                Console.WriteLine("Incorrect arguments.Specify them as \"first path\" \"second path\"");
                return;
            }
             

            arg = arg.Substring(1);
            int secondQuote = arg.IndexOf('"');

            if(secondQuote == -1)
            {
                Console.WriteLine("Incorrect arguments.Specify them as \"first path\" \"second path\"");
                return;
            }
            string sourcePath, destinationPath;

            try
            {
                sourcePath = arg.Substring(0, secondQuote);
                destinationPath = arg.Substring(secondQuote + 3);
                destinationPath = destinationPath.Substring(0, destinationPath.Length-1); // remove the last quote
            }
            catch(Exception)
            {
                Console.WriteLine("Incorrect arguments.Specify them as \"first path\" \"second path\"");
                return;
            }
           
            // move the files
            try
            {
                filesystem.move(sourcePath, destinationPath);
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                foreach (string s in filesystem.getMessages())
                    Console.WriteLine(s);
            }
        }
        
        private void remove(string path)
        {
            if (filesystem.removeFile(path) == false)
                Console.WriteLine("Requested path doesn't exist.");
         
            foreach (string s in filesystem.getMessages())
                Console.WriteLine(s);
        }

        private void changeDirectory(string path)
        {
            if (filesystem.changeDirectory(path) == false)
                Console.WriteLine("Requested directory doesn't exist!");
          
            foreach (string s in filesystem.getMessages())
                Console.WriteLine(s);
        }

        private void uploadFile(string fileName)
        {
            // upload file located in the upload folder
            try
            {
                filesystem.uploadFile(fileName);
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
        public void parseCommand(string command)
        {
            string[] parts = command.Split(' ');

            if(command.Equals("ls"))
            {
                listDir();
                return;
            }
            else if(command.Equals("cls"))
            {
                Console.Clear();
                return;
            }
            else if(command.Equals("maketext"))
            {
                makeTextFile();
                return;
            }

            if (parts == null || parts.Length < 2)
            {
                Console.WriteLine("Incorrect input");
                return;
            }
            try
            {
                switch (parts[0])
                {
                    case "open":
                        openFile(command.Substring(5));
                        break;
                    case "mkdir":
                        makeDir(command.Substring(6));
                        break;
                    case "mv":
                        move(command.Substring(3));
                        break;
                    case "edit":
                        editTextFile(command.Substring(5));
                        break;
                    case "rm":
                        remove(command.Substring(3));
                        break;
                    case "cd":
                        changeDirectory(command.Substring(3));
                        break;
                    case "upload":
                        uploadFile(command.Substring(7));
                        break;

                    default:
                        Console.WriteLine("Unknown command.");
                        break;
                }
            }
            catch (IndexOutOfRangeException)
            {
                Console.WriteLine("Incorrect input");
            }
        }
        
        void deserializeFilesystem()
        {
            try
            {
                using (FileStream stream = new FileStream("Filesystem.bin", FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    BinaryFormatter bf = new BinaryFormatter();

                    Filesystem tempFS = (Filesystem)bf.Deserialize(stream);
                    filesystem = new Filesystem(encryptionKey, hashingAlgorithm, encryptionAlgorithm, keyPair, tempFS);
                }
            }
            catch(Exception)
            {
                filesystem = new Filesystem(encryptionKey, hashingAlgorithm, encryptionAlgorithm, keyPair); // nothing to deserialize
            }
        }

        void serializeFileSystem()
        {
            using (FileStream stream = new FileStream("Filesystem.bin", FileMode.OpenOrCreate)) 
            {
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(stream, filesystem);
            }
        }

        static void Main(string[] args)
        {
            Program obj = new Program();
            obj.deserializeDatabase();
            while(true)
            {
                try
                {
                    obj.login();
                    break;
                }
                catch(Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
            obj.deserializeFilesystem();

            //obj.filesystem = new Filesystem(obj.encryptionKey, obj.hashingAlgorithm, obj.encryptionAlgorithm, obj.keyPair);

            while(true)
            {
                string command = Console.ReadLine();
                if (command.Equals("exit"))
                {
                    obj.filesystem.encryptFileSystem();
                    obj.serializeFileSystem();
                    return;
                }
                else if(command.Equals("help"))
                {
                    Console.WriteLine("open file_name - open a file");
                    Console.WriteLine("mkdir path - create folder");
                    Console.WriteLine("mv source_path destination_path - move files/folders");
                    Console.WriteLine("maketext - create a txt file");
                    Console.WriteLine("edit txt_file_path - edit a txt file");
                    Console.WriteLine("rm path - remove a file/folder at specified path");
                    Console.WriteLine("cd path - change working directory to specified path");
                    Console.WriteLine("cls - clear screen");
                    Console.WriteLine("ls - display contents of the working directory");
                    Console.WriteLine("upload file_name - upload file specified by file_name located in upload folder");
                }
                else
                    obj.parseCommand(command);
            }
           

            /*obj.deserializeDatabase(); // call on startup every time

            //obj.registerUser();
            while(true)
            {
                try
                {
                    obj.login();
                    break;
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }*/

            /*
            string fileName = "raspored.png";
            obj.storeFile(obj.loadFile(@"C:\Users\Korisnik\Desktop\" + fileName), fileName);
            obj.openFile(fileName);

            System.Diagnostics.Process.Start(fileName);*/


            /*
            byte[] data = Encoding.UTF8.GetBytes("my longest message that will be entered in this example");
            byte[] key = Encoding.UTF8.GetBytes("a key that unlocks doors will 12");
            byte[] IV = new byte[8];
            CryptoUtilities.getRandomData(IV);

            byte[] cipherText = CryptoUtilities.encryptDecryptChaCha(true, data, key, IV);
            byte[] deciphered = CryptoUtilities.encryptDecryptChaCha(true, cipherText, key, IV);
            Console.WriteLine(Encoding.UTF8.GetString(cipherText));
            Console.WriteLine(Encoding.UTF8.GetString(deciphered));*/


        }
    }
}
