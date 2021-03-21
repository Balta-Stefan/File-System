using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;
using static CustomFS.CryptoUtilities;

namespace CustomFS
{
    [Serializable]
    class KIRZFilesystem : Filesystem
    {
        // The user will have to manually move the file from the virtual upload folder to whenever he wants (inside virtual file system).


        /*public class LoginCredentials
        {
            public string username;
            public byte[] password;
            public X509Certificate clientCertificate;

            public LoginCredentials(string username, byte[] password, X509Certificate clientCertificate) { this.username = username; this.password = password; this.clientCertificate = clientCertificate; }

            ~LoginCredentials()
            {
                Array.Clear(password, 0, password.Length);
            }
        }

        private File root;
        private File uploadFolder;
        private readonly File sharedFolder;
        private readonly string rootName;

        public static readonly string uploadFolderName = "upload";
        public static readonly string downloadFolderName = "download";
        public static readonly string sharedFolderName = "shared";


        [NonSerialized] private byte[] encryptionKey;
        [NonSerialized] private readonly integrityHashAlgorithm hashingAlgorithm;
        [NonSerialized] private readonly encryptionAlgorithms encryptionAlgorithm;
        [NonSerialized] private readonly AsymmetricCipherKeyPair keyPair;
        [NonSerialized] private readonly Queue<string> messageQueue = new Queue<string>();
        [NonSerialized] private File workingDirectory;


        private readonly List<File> requiresEncryption = new List<File>();*/


        public KIRZFilesystem(byte[] encryptionKey, integrityHashAlgorithm hashingAlgorithm, encryptionAlgorithms encryptionAlgorithm, AsymmetricCipherKeyPair keyPair, LoginCredentials loginCreds) : base(encryptionKey, hashingAlgorithm, encryptionAlgorithm, keyPair, loginCreds)
        {

            
        }

        /// <summary>
        /// Call this method to retrieve contents of the shared folder from the server.
        /// </summary>
        private void updateSharedFolder()
        {

        }

        public override void login(LoginCredentials loginCreds)
        {
            
            // use sockets

            // checks whether login credentials are correct by decrypting the root directory.If they aren't, an exception is thrown.

            // get own root directory from the server
            // encrypt the login credentials using server's public key
            try
            {
                using (FileStream stream = new FileStream("Filesystem.bin", FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    BinaryFormatter bf = new BinaryFormatter();
                    root = (File)bf.Deserialize(stream);
                    sharedFolder = root.searchDirectory(sharedFolderName);
                    uploadFolder = root.searchDirectory(uploadFolderName);
                }
            }
            catch (Exception) // no file found
            {
                //filesystem = new Filesystem(encryptionKey, hashingAlgorithm, encryptionAlgorithm, keyPair); // nothing to deserialize
                root = new File(loginCreds.username, null, true, DateTime.Now);
                sharedFolder = new File(sharedFolderName, root, true, DateTime.Now);
                uploadFolder = new File(uploadFolderName, root, true, DateTime.Now);
                root.insertNewFile(sharedFolder);
                root.insertNewFile(uploadFolder);

                // encrypt the root directory to avoid integrity warnings
                root.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
            }

            //root.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm); // will throw an exception if not successful
            // end of root directory retrieval

            // obtain the shared folder - to do
        }


        /// <summary>
        /// Create text file in the working directory.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="contents"></param>
        public void makeTextFile(string fileName, string contents)
        {
            if (fileName.EndsWith(".txt") == false)
                fileName += ".txt";

            if (workingDirectory.searchDirectory(fileName) != null)
                throw new Exception("File already exists");

            File newFile = new File(fileName, workingDirectory, false, DateTime.Now);
            newFile.setData(Encoding.UTF8.GetBytes(contents));

            workingDirectory.insertNewFile(newFile);
            //currentFolder.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);

            // encrypt the parent folder to avoid integrity warnings.Also encrypt the new text file.
            newFile.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
            workingDirectory.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
            //requiresEncryption.Add(parentDir);
            //requiresEncryption.Add(newFile);
        }



        /*
        /// <summary>
        /// Creates a new file.
        /// </summary>
        /// <returns>False if the file already exists.True if file creation is successful.</returns>
        public bool addFile(string name, File parentDir, bool isDir)
        {
            //File newFile = new File(path, parentDir, isDir, DateTime.Now);
            // check if the file exists
            if(parentDir.directoryContents.search(name) != null)
                return false;

            File newFile = new File(name, parentDir, isDir, DateTime.Now);
            parentDir.directoryContents.insert(newFile);

            requiresEncryption.Add(newFile);
            requiresEncryption.Add(parentDir);

            return true;
        }*/


        /// <summary>
        /// Called when the file system has to be "sealed" at the end of session.
        /// </summary>
        public override void closeFilesystem()
        {
            root.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);

            foreach (File f in requiresEncryption)
                f.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);

            requiresEncryption.Clear();

            // serialize the file
            BinaryFormatter bf = new BinaryFormatter();
            using(Stream stream = new FileStream("Filesystem.bin", FileMode.Create, FileAccess.Write))
            {
                bf.Serialize(stream, root);
            }
            Array.Clear(encryptionKey, 0, encryptionKey.Length);


            //saveFilesystem();
            //addChangesToSharedDirectory();
        }
    }
}
