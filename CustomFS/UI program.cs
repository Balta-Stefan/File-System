using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
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
using SharedClasses;
using static SharedClasses.CryptoUtilities;

namespace CustomFS
{

    [Serializable]
    class Program
    {
        //static readonly int port = 25000;
        //static readonly string serverIP = "127.0.0.1";



        //private SessionInfo session;
        //private Credentials creds;

        public AsymmetricCipherKeyPair keyPair;
        //public integrityHashAlgorithm hashingAlgorithm;
        //public encryptionAlgorithms encryptionAlgorithm;
        public KIRZFilesystem filesystem;
        public AsymmetricKeyParameter serverPublicKey;
        //public File workingDirectory;

        //public File root;
        public readonly List<SharedClasses.File> requireEncryption = new List<SharedClasses.File>();

        private static readonly string CAfilename = "CA.pem";
        //private static string userDatabaseFilename = "User database.bin";
        //private static string usersPublicKeysDatabaseFilename = "Public key database.bin";
        //private static readonly string serializationFilename = "Filesystem.bin";
        //private static readonly string sharedFilename = "shared.bin";

        string username;
        byte[] password;
        X509Certificate clientCertificate;

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
                else if (((int)key.KeyChar) >= 32 && ((int)key.KeyChar <= 126))
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


        public AsymmetricKeyParameter getUserPublicKey(string userName)
        {
            // get the public key from the server
            SharedClasses.Message.PublicKeyRequest request = new SharedClasses.Message.PublicKeyRequest(userName, serverPublicKey);
            SharedClasses.Message.PublicKeyRequest response = (SharedClasses.Message.PublicKeyRequest)KIRZFilesystem.sendDataToServer(KIRZFilesystem.serializeObject(request));
            response.decrypt(serverPublicKey);

            return response.decodePublicKey();
        }
        
        /// <param name="toShareArgs">Format: "username of the receiver" "file path"</param>
        public void shareFile(string toShareArgs)
        {
            // bool Filesystem.shareWith(string userName, File file)

            if (toShareArgs.Length < 5)
            {
                Console.WriteLine("Incorrect arguments.Specify them as \"receiver\" \"file path\"");
                return;
            }

            toShareArgs = toShareArgs.Substring(1);
            int secondQuote = toShareArgs.IndexOf('"');

            if (secondQuote == -1)
            {
                Console.WriteLine("Incorrect arguments.Specify them as \"receiver\" \"file path\"");
                return;
            }
            string receiver, filePath;
            AsymmetricKeyParameter receiverPublicKey;

            try
            {
                receiver = toShareArgs.Substring(0, secondQuote);
                filePath = toShareArgs.Substring(secondQuote + 3);
                filePath = filePath.Substring(0, filePath.Length - 1); // remove the last quote
            }
            catch (Exception)
            {
                Console.WriteLine("Incorrect arguments.Specify them as \"receiver\" \"file path\"");
                return;
            }

            try
            {
                receiverPublicKey = getUserPublicKey(receiver);
                if (receiverPublicKey == null)
                {
                    Console.WriteLine("Wanted user doesn't exist");
                    return;
                }
            }
            catch(Exception e)
            {
                Console.WriteLine("Error obtaining the user's public key.");
                return;
            }

            try
            {
                SharedClasses.File fileForSharing = filesystem.findFile(filePath);
                if(fileForSharing == null)
                {
                    Console.WriteLine("Specified file doesn't exist.");
                    return;
                }

                // share the file
                SharedClasses.File fileToSend = filesystem.shareFile(fileForSharing, receiverPublicKey);

                // send the file to server
                SharedClasses.Message.ShareFile shareMessage = new Message.ShareFile(fileToSend, serverPublicKey);
                Message.ShareFile reply = (Message.ShareFile)KIRZFilesystem.sendDataToServer(KIRZFilesystem.serializeObject(shareMessage));
                reply.decrypt(serverPublicKey);
                if(reply.fileToShare == null)
                {
                    Console.WriteLine("Error - couldn't obtain the shared directory from server.");
                    return;
                }
                // update the shared directory on the file system
                filesystem.updateSharedDirectory(reply.fileToShare);

                //Console.WriteLine(reply.message);
            }
            catch (Exception)
            {
                Console.WriteLine("Cannot share the specified file");
            }
        }
        private void openFile(string fileName)
        {
            // check if the file exists in the virtual filesystem
            SharedClasses.File toOpen;
            try
            {
                toOpen = filesystem.downloadFile(fileName);
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

            // the program will block until this process is closed (WaitForExit() call)
            Process tempProcess = new Process
            {
                StartInfo = new ProcessStartInfo(KIRZFilesystem.downloadFolderName + Path.DirectorySeparatorChar + toOpen.name)
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
            List<SharedClasses.File> files = filesystem.listWorkingDirectory();

            foreach (SharedClasses.File f in files)
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
                else if (key.Key == ConsoleKey.Enter || ((int)key.KeyChar) >= 32 && ((int)key.KeyChar <= 126))
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
            SharedClasses.File wantedFile = filesystem.findFile(fileName);
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

            string text = null;
            try
            {
                text = System.IO.File.ReadAllText(KIRZFilesystem.downloadFolderName + Path.DirectorySeparatorChar + wantedFile.name);
            }
            catch(Exception)
            {
                Console.WriteLine("Error reading the downloaded file.");
                return;
            }

            char[] textArray = text.ToCharArray();
            //int limit = text.Length;

            string str = enterText(textArray);

            // write string to file
            try
            {
                System.IO.File.WriteAllText(KIRZFilesystem.downloadFolderName + Path.DirectorySeparatorChar + wantedFile.name, str);
            }
            catch (Exception)
            {
                Console.WriteLine("Error writing the downloaded file.");
                return;
            }

          
            filesystem.setFileData(wantedFile, Encoding.UTF8.GetBytes(str));
            //wantedFile.setData(fileStream.ToArray());
            //requireEncryption.Add(wantedFile);
            //filesystem.checkEncryptionUtility(wantedFile);
            string tmp = KIRZFilesystem.downloadFolderName + Path.DirectorySeparatorChar + fileName;
            System.IO.File.Delete(KIRZFilesystem.downloadFolderName + Path.DirectorySeparatorChar + wantedFile.name);
            
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
            try
            {
                filesystem.removeFile(path);
            }
            catch(Exception)
            {
                Console.WriteLine("There has been an error while trying to delete the file.");
            }
         
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

        private void downloadFile(string filePath)
        {
            try
            {
                filesystem.downloadFile(filePath);
            }
            catch(Exception e) { Console.WriteLine(e.Message); }
        }

        private void displayCurrentPath()
        {
            Console.WriteLine(filesystem.getCurrentPath());
        }
        public void parseCommand(string command)
        {
            string[] parts = command.Split(' ');

            // commands without arguments
            switch(command)
            {
                case "ls":
                    listDir();
                    return;
                case "cls":
                    Console.Clear();
                    return;
                case "maketext":
                    makeTextFile();
                    return;
                case "pwd":
                    displayCurrentPath();
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
                    case "share":
                        shareFile(command.Substring(6));
                        break;
                    case "download":
                        downloadFile(command.Substring(9));
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
        
        object deserializeFile(string fileName)
        {
            try
            {
                using (FileStream stream = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    BinaryFormatter bf = new BinaryFormatter();
                    return bf.Deserialize(stream);
                }
            }
            catch(Exception)
            {
                return null;
            }
        }

        private void printHelp()
        {
            Console.WriteLine("+===============================================================================================================+");
            Console.WriteLine("|help - display this                                                                                            |");
            Console.WriteLine("|open file_name - open a file with the default program                                                          |");
            Console.WriteLine("|pwd - display current path                                                                                     |");
            Console.WriteLine("|mkdir path - create folder                                                                                     |");
            Console.WriteLine("|mv source_path destination_path - move files/folders                                                           |");
            Console.WriteLine("|maketext - create a txt file                                                                                   |");
            Console.WriteLine("|edit txt_file_path - edit a txt file                                                                           |");
            Console.WriteLine("|rm path - remove a file/folder at specified path                                                               |");
            Console.WriteLine("|cd path - change working directory to specified path                                                           |");
            Console.WriteLine("|cls - clear screen                                                                                             |");
            Console.WriteLine("|ls - display contents of the working directory                                                                 |");
            Console.WriteLine("|upload file_name - upload file specified by file_name located in upload folder.Directories cannot be uploaded. |");
            Console.WriteLine("|download file_path - download the specified file to the download directory.                                    |");
            Console.WriteLine("|share \"receiver\" \"file_path\" - share the selected file with the specified receiver.                        |");
            Console.WriteLine("|                                                                                                               |");
            Console.WriteLine("+===============================================================================================================+");
        }
        void runProgram()
        {
            //filesystem = new KIRZFilesystem(creds, keyPair);
            SharedClasses.Message.Login loginInfo = new SharedClasses.Message.Login(username, password, clientCertificate, serverPublicKey);
            filesystem = new KIRZFilesystem(loginInfo, keyPair, serverPublicKey);

            Console.Clear();
            printHelp();

            while (true)
            {
                string command = Console.ReadLine();
                if (command.Equals("exit"))
                {
                    filesystem.closeFilesystem();
                    return;
                }
                else if (command.Equals("help"))
                    printHelp();
                else
                    parseCommand(command);
            }
        }
        public void register()
        {
            string userName;
            byte[] pass;

            Console.WriteLine("Enter username: ");
            userName = Console.ReadLine();


            while (true)
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

            //HashedPassword passwordData = new HashedPassword(pass, hashAlgorithm, encryptionAlgorithm);

            // create the digital certificate
            // The user must supply a filename that contains his private key in PEM format.
            // in the future, add support for eliptic curve cryptography.

            AsymmetricCipherKeyPair keyPair = null;
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
                using (StreamReader fileStream = System.IO.File.OpenText(privateKeyFilename))
                {
                    PemReader reader = new PemReader(fileStream);
                    try
                    {
                        keyPair = (AsymmetricCipherKeyPair)reader.ReadObject();
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("Error reading the given private key.");
                        continue;
                    }
                }


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
            string organizationName = "ETF";// Console.ReadLine();
            Console.WriteLine("Enter organization unit: ");
            string organizationUnit = "RI";// Console.ReadLine();
            Console.WriteLine("Enter state: ");
            string state = "RS";// Console.ReadLine();
            Console.WriteLine("Enter country: ");
            string country = "BiH";// Console.ReadLine();

            byte[] keyDerivationSalt = new byte[16];
            CryptoUtilities.getRandomData(keyDerivationSalt);
            Pkcs10CertificationRequest csr = CryptoUtilities.generateCSR(keyPair, commonName, organizationName, organizationUnit, state, country);
            X509Certificate serverCertificate = CryptoUtilities.loadCertFromFile(CAfilename);

            // create and encrypt the root
            SharedClasses.File root = new SharedClasses.File(userName, null, true, DateTime.Now);
            byte[] symmetricKey = CryptoUtilities.scryptKeyDerivation(pass, keyDerivationSalt, CryptoUtilities.defaultSymmetricKeySize);
            root.encrypt(symmetricKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashAlgorithm, encryptionAlgorithm);

            SharedClasses.Message.Registration registrationCredentials = new SharedClasses.Message.Registration(userName, pass, csr, SharedClasses.File.serializeFile(root), keyDerivationSalt, serverPublicKey, hashAlgorithm, encryptionAlgorithm);

            SharedClasses.Message.RegistrationReply reply = (SharedClasses.Message.RegistrationReply)KIRZFilesystem.sendDataToServer(KIRZFilesystem.serializeObject(registrationCredentials));
            reply.decrypt(serverPublicKey);

            if (reply.encodedSignedCertificate == null)
                throw new Exception(reply.message);

            Console.WriteLine(reply.message);
            // dump the certificate
            CryptoUtilities.dumpToPEM(reply.decodeCertificate(), userName + ".pem");
        }

        public void get_login_credentials()
        {
            Console.WriteLine("Username:");
            username = Console.ReadLine();
            password = inputPassword();

            // handle the client certificate

            Console.WriteLine("Input the name of the certificate in PEM format:");
            string certFilename = Console.ReadLine();

            // check if the file exists
            if (System.IO.File.Exists(certFilename) == false)
            {
                Console.WriteLine("Given file doesn't exist.Put it into the directory where exe is located.");
                return;
            }
            else
            {
                StreamReader fileStream = System.IO.File.OpenText(certFilename);
                PemReader reader = new PemReader(fileStream);
                try
                {
                    clientCertificate = (X509Certificate)reader.ReadObject();
                }
                catch (Exception)
                {
                    //Console.WriteLine("Error reading the given certificate file.");
                    Console.WriteLine("Error reading the given certificate file.");
                    return;
                }
                finally
                {
                    fileStream.Close();
                }

                X509Certificate rootCert = null;
                fileStream = System.IO.File.OpenText(CAfilename);
                reader = new PemReader(fileStream);
                try
                {
                    rootCert = (X509Certificate)reader.ReadObject();
                    serverPublicKey = rootCert.GetPublicKey();
                }
                catch (Exception)
                {
                    Console.WriteLine("Error reading CA certificate.");
                    return;
                }
                finally
                {
                    fileStream.Close();
                }
            }

            Console.WriteLine("Enter the name of the file that containts your RSA key pair: ");
            string keypairFile = Console.ReadLine();
            if (System.IO.File.Exists(keypairFile) == false)
            {
                Console.WriteLine("Given file doesn't exist.Put it into the directory where exe is located");
                return;
            }

            keyPair = CryptoUtilities.load_keypair_from_file(keypairFile);
          
            runProgram();
        }

        void setup()
        {
            if (System.IO.File.Exists(CAfilename) == false)
                throw new Exception("Cannot find CA certificate called " + CAfilename + ".");
            // load CA public key 
            using (StreamReader fileStream = System.IO.File.OpenText(CAfilename))
            {
                PemReader reader = new PemReader(fileStream);
                try
                {
                    X509Certificate CAcert = (X509Certificate)reader.ReadObject();
                    serverPublicKey = CAcert.GetPublicKey();
                }
                catch (Exception)
                {
                    throw new Exception("Error reading the CA certificate key.");
                }
            }
        }

        static void Main(string[] args)
        {
            Program obj = new Program();
            try
            {
                obj.setup();
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
                Console.ReadLine();
                return;
            }


            while (true)
            {
                Console.WriteLine("1)Login");
                Console.WriteLine("2)Register");
                Console.WriteLine("3)Exit");

                int choice = 0;
                try
                {
                    choice = Int32.Parse(Console.ReadLine());
                }
                catch (Exception) { Console.WriteLine("Incorrect input"); }

                try
                {
                    switch (choice)
                    {
                        case 1:
                            obj.get_login_credentials();
                            Console.WriteLine(obj.clientCertificate.ToString());
                            break;
                        case 2:
                            obj.register();
                            break;
                        case 3:
                            return;
                        default:
                            Console.WriteLine("Incorrect input.");
                            break;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
        
                //runProgram();
            }
          
            //string temp = Console.ReadLine();
            
            /*RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair keypair = generator.GenerateKeyPair();
            byte[] data = Encoding.UTF8.GetBytes("hello mate this is a secret message!");

            byte[] encrypted = RSAOAEP(true, keypair.Private, data);

            Array.Clear(data, 0, data.Length);
            data = null;

            byte[] decrypted = RSAOAEP(false, keypair.Public, encrypted);

            Console.WriteLine(Encoding.UTF8.GetString(decrypted));*/
           
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
