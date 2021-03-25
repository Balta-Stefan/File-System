using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharedClasses;
using static SharedClasses.CryptoUtilities;

namespace CustomFS
{
    // Lista stvari za uraditi:
    // 1)CRL lista
    // 2)Klijent i server programi
    // 3)Registracija - server mora poslati klijentu njegov certifikat nakon uspjesne registracije - ili ne mora?Pitati asistenta.

    // Problemi:
    // 1)Gdje ce se cuvati IV potreban za izvodjenje kljuca za enkripciju iz sifre (Scrypt)?Moze se cuvati na serveru...
    // 2)Server mora provjeriti common name na certifikatu primaoca.Ovo trenutno ne radi.
    // 3)Server mora provjeriti CRL list - trenutno se ne radi.


    [Serializable]
    abstract class Filesystem
    {
       

        protected SharedClasses.File root;
        protected SharedClasses.File uploadFolder;
        protected SharedClasses.File sharedFolder;
        protected readonly string rootName;

        public static readonly string uploadFolderName = "upload";
        public static readonly string downloadFolderName = "download";
        public static readonly string sharedFolderName = "shared";


        [NonSerialized] protected byte[] encryptionKey;
        [NonSerialized] protected integrityHashAlgorithm hashingAlgorithm;
        [NonSerialized] protected encryptionAlgorithms encryptionAlgorithm;
        [NonSerialized] protected readonly AsymmetricCipherKeyPair keyPair;
        [NonSerialized] private readonly Queue<string> messageQueue = new Queue<string>();
        [NonSerialized] protected SharedClasses.File workingDirectory;

        protected readonly List<SharedClasses.File> requiresEncryption = new List<SharedClasses.File>();

        ~Filesystem()
        {
            if(encryptionKey != null)
                Array.Clear(encryptionKey, 0, encryptionKey.Length);
        }
        /// <summary>
        /// When calling this ctor, login method is responsible for assigning hashingAlgorithm, encryptionAlgorithm and keyPair to the correct values.
        /// </summary>
        public Filesystem(SharedClasses.Message.Login loginCreds, AsymmetricCipherKeyPair keyPair)
        {
            this.keyPair = keyPair;
            login(loginCreds);

            workingDirectory = root;
            rootName = root.name;

            if (Directory.Exists(uploadFolderName) == false)
                Directory.CreateDirectory(uploadFolderName);
            if (Directory.Exists(downloadFolderName) == false)
                Directory.CreateDirectory(downloadFolderName);


            try
            {
                root.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);
            }
            catch(Exception e)
            {
                messageQueue.Enqueue(e.Message);
                throw new Exception("Cannot decrypt the root directory.");
            }
        }
        public Filesystem(byte[] encryptionKey, integrityHashAlgorithm hashingAlgorithm, encryptionAlgorithms encryptionAlgorithm, AsymmetricCipherKeyPair keyPair, SharedClasses.Message.Login loginCreds)
        {
            this.encryptionKey = (byte[])encryptionKey.Clone();
            this.hashingAlgorithm = hashingAlgorithm;
            this.encryptionAlgorithm = encryptionAlgorithm;
            this.keyPair = keyPair;

            login(loginCreds);
            workingDirectory = root;
            rootName = root.name;

            if (Directory.Exists(uploadFolderName) == false)
                Directory.CreateDirectory(uploadFolderName);
            if (Directory.Exists(downloadFolderName) == false)
                Directory.CreateDirectory(downloadFolderName);

            try
            {
                root.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);
            }
            catch(Exception e)
            {
                messageQueue.Enqueue(e.Message);
            }
        }

        public List<SharedClasses.File> listWorkingDirectory()
        {
            List<SharedClasses.File> files;
            workingDirectory.traverseDirectory(out files);

            return files;
        }
        
        /// <param name="path">Directory name or path (absolute/relative).</param>
        /// <returns>True for success, false otherwise.</returns>
        public void makeDirectory(string path)
        {
            if (findFile(path) != null)
                throw new Exception("File with the given name already exists.");

            SharedClasses.File parentDir = findParent(path);
            if (parentDir == sharedFolder)
                throw new Exception("Cannot make a directory in the shared directory.");

            string dirName = Path.GetFileName(path);

            if (parentDir == null)
                throw new Exception("Parent doesn't exist.");
            if (parentDir.isDir == false)
                throw new Exception("Parent isn't a directory.");

            parentDir.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);
            SharedClasses.File newDir = new SharedClasses.File(dirName, parentDir, true, DateTime.Now);
            parentDir.insertNewFile(newDir);

            // encrypt the directories to avoid integrity warnings
            newDir.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
            parentDir.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
        }

        private SharedClasses.File findParent(string path)
        {
            string dirName = Path.GetFileName(path);
            if (path.IndexOf(Path.DirectorySeparatorChar) == -1)
                return workingDirectory;

            int toRemoveLength = 1 + dirName.Length; // 1 is added because of path separator (slash)

            path = path.Remove(path.Length - toRemoveLength);

            SharedClasses.File parentDir = findFile(path);

            return parentDir;
        }
        public void removeFile(string path)
        {
            SharedClasses.File toRemove = findFile(path);

            if (toRemove == null)
                throw new Exception("Requested file doesn't exist!");

            if (toRemove.name.Equals(rootName) || toRemove.name.Equals(uploadFolderName) || toRemove.name.Equals(sharedFolderName))
                throw new Exception("Cannot remove the selected folder!");

            if (toRemove.name.Equals(workingDirectory.name))
                workingDirectory = toRemove.parentDir;

            // the problem occurs when toRemove doesn't have a parent.
            if (toRemove.parentDir != null)
            {
                toRemove.parentDir.deleteFile(toRemove);
                // encrypt the parent directory to avoid integrity warnings
                toRemove.parentDir.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
            }
        }

        public bool changeDirectory(string dirName)
        {
            SharedClasses.File newDir = findFile(dirName);

            if (newDir == null)
                return false;
            if (newDir.isDir == false)
                return false;

            workingDirectory = newDir;
            if (newDir.name.Equals(sharedFolderName))
                return true; // no need to decrypt or verify the shared directory

            workingDirectory.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);
            return true;
        }

        /// <summary>
        /// Returns the wanted file, if it exists, without decrypting it.The whole path from top to the wanted file will be decrypted.
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        public SharedClasses.File findFile(string path)
        {
            // parse the paths
            if (path.Equals(rootName))
                return root;
            string[] source = path.Split(Path.DirectorySeparatorChar);

            // if a path begins with a slash, treat it as absolute path
            // else, treat it as relative path such that the first element is the name of a file or folder in the current folder.
            //File wantedFile = null;
            SharedClasses.File currentPath;

            int loopCounter = 0;
            if (source[0].Equals(rootName))
            {
                currentPath = root;// absolute path
                loopCounter = 1;
            }
            else
                currentPath = workingDirectory; // relative path


            // possibilities:
            // absolute path
            // example: \first\second\third
            // search has to begin from the root and the next file that has to be searched within the root is at source[1]
            // iterate from 1 to source.Length - 1 inclusively

            // relative path
            // example: first\second\third
            // search has to begin from currentFolder, the next file that is searched for is at source[0]
            // iterate from 0 to source.Length - 1 inclusively


            for (; loopCounter <= source.Length - 1; loopCounter++)
            {
                try
                {
                    // is this decryption necessary at all?method searchDirectory doesn't need decrypted files.
                    currentPath.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);
                }
                catch (Exception e)
                {
                    messageQueue.Enqueue(e.Message);
                }
                if (source[loopCounter].Equals(".."))
                    currentPath = currentPath.parentDir;
                else
                    currentPath = currentPath.searchDirectory(source[loopCounter]);
                //currentPath = currentPath.directoryContents.search(source[i]);
                if ((currentPath == null || currentPath.isDir == false) && loopCounter != (source.Length - 1)) // this will cause problems if the last item is a file and not a directory
                    return null;
            }

            /*if (i < source.Length)
            {
                try
                {
                    currentPath.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);
                }
                catch (Exception e)
                {
                    messageQueue.Enqueue(e.Message);
                }
                wantedFile = currentPath.searchDirectory(source[i]);
                //wantedFile = currentPath.directoryContents.search(source[i]); // this is either a directory or a file, everything before this was a directory.
            }*/

            return currentPath;
        }

        /// <summary>
        /// Move a file from source path to destination path.
        /// </summary>
        /// <param name="sourcePath"></param>
        /// <param name="destinationPath"></param>
        /// <exception cref="Exception">If moving isn't successful.</exception>
        /// <returns></returns>
        public bool move(string sourcePath, string destinationPath)
        {
            SharedClasses.File sourceFile = findFile(sourcePath);
            if (sourceFile == null)
                throw new Exception("Source file doesn't exist");

            SharedClasses.File destinationFile = findFile(destinationPath);
            if (destinationFile == null)
                throw new Exception("Destination file doesn't exist");
            if (destinationFile == sharedFolder)
                throw new Exception("Cannot move files to the shared directory.");

            // check if such file already exists at the destination
            string fileName = Path.GetFileName(sourcePath);
            if (destinationFile.isDir == false)
                throw new Exception("Destination isn't a folder!");

            if (destinationFile.searchDirectory(fileName) != null)
                throw new Exception("File already exists!");

            sourceFile.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);
            // sourceFile.parentDir will be decrypted by the findFile method
            sourceFile.parentDir.deleteFile(sourceFile); // remove the file from the old location
            sourceFile.parentDir.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm); // change the signature of the parent directory to avoid warnings of directory corruption

            destinationFile.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm); // decrypt because the encryption below requires the file to be decrypted
            destinationFile.insertNewFile(sourceFile);
            destinationFile.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);


            sourceFile.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm); // decrypt because changeParentDir requires the parent to be decrypted
            //sourceFile.changeParentDir(destinationFile);
            sourceFile.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm); // encrypt the file and sign it after moving it

            //sourceFile.parentDir = destinationFile;

            
            //sourceFile.parentDir.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);
            //sourceFile.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);
            //destinationFile.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);

            return true;
        }

        public string getCurrentPath()
        {
            return workingDirectory.getAbsolutePath();
        }

        public Queue<string> getMessages()
        {
            Queue<string> temp = new Queue<string>(messageQueue);
            messageQueue.Clear();
            return temp;
        }

        /// <summary>
        /// Creates the wanted file in temp folder.
        /// </summary>
        /// <param name="parentDir">Parent folder.</param>
        /// <param name="name">Name of the wanted file.</param>
        /// <returns>The wanted file.</returns>
        public SharedClasses.File downloadFile(string fileName, SharedClasses.File wantedFile = null)
        {
            //File wantedFile = findFile(fileName);
            if (wantedFile == null)
                wantedFile = findFile(fileName);

            if (wantedFile == null)
                throw new Exception("Wanted file doesn't exist.");

            // first decrypt the file
            wantedFile.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);

            if (wantedFile.isDir == true)
                throw new Exception("Cannot download folders!");

            if (Directory.Exists(downloadFolderName) == false)
                Directory.CreateDirectory(downloadFolderName);

            // create the file
            using (MemoryStream stream = new MemoryStream(wantedFile.getData()))
            {
                using (FileStream file = new FileStream(downloadFolderName + Path.DirectorySeparatorChar + wantedFile.name, FileMode.Create, System.IO.FileAccess.Write))
                    stream.CopyTo(file);
            }

            return wantedFile;
        }
        /// <summary>
        /// Upload the file specified by the given file name.
        /// </summary>
        /// <param name="fileName">Name of the file.</param>
        /// <returns>False if specified file doesn't exist or if it specifies a folder.True if file upload is successful.</returns>
        public void uploadFile(string fileName)
        {
            if (Directory.Exists(uploadFolderName + Path.DirectorySeparatorChar + fileName) == true)
                throw new Exception("Specified file name is a directory.");

            if (System.IO.File.Exists(uploadFolderName + Path.DirectorySeparatorChar + fileName) == false)
                throw new Exception("Specified file doesn't exist.");

            // check if such file already exists in the upload folder
            if (findFile(fileName) != null)
                throw new Exception("Such file already exists in the upload folder.");


            if (Directory.Exists(uploadFolderName) == false)
                Directory.CreateDirectory(uploadFolderName);
            // serialize the file
            using (MemoryStream fileStream = loadFile(uploadFolderName + Path.DirectorySeparatorChar + fileName))
            {
                // Encrypt and sign the file.
                uploadFolder.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);
                SharedClasses.File newFile = new SharedClasses.File(fileName, uploadFolder, false, DateTime.Now);
                newFile.setData(fileStream.ToArray());

                newFile.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);

                uploadFolder.insertNewFile(newFile);
                //uploadFolder.directoryContents.insert(newFile);
                uploadFolder.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
            }
        }
        
        private MemoryStream loadFile(string path)
        {
            MemoryStream inMemoryCopy = new MemoryStream();
            using (FileStream fs = System.IO.File.OpenRead(path))
            {
                fs.CopyTo(inMemoryCopy);
            }
            inMemoryCopy.Position = 0;

            return inMemoryCopy;
        }

        /// <summary>
        /// Only files can be shared.Directories aren't allowed.
        /// </summary>
        /// <param name="file">File to be shared.Directory sharing is not allowed.</param>
        public SharedClasses.File shareFile(SharedClasses.File file, AsymmetricKeyParameter publicKey)
        {
            // The problem with sharing is that serializing the file in the shared directory will also serialize the entire user's file system because of the parentDir link.This is unacceptable.
            // This will be solved in the following way: this method will return the file with parentDir set to null.The user will then send this file to the server.
            // after that, the server will send back the whole shared directory back.

            if (file.isDir == true)
                throw new Exception("Directory sharing not allowed!");
            file.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);
            SharedClasses.File sharedFile = file.share(publicKey, encryptionAlgorithm, hashingAlgorithm);
            //sharedFolder.insertNewFile(sharedFile);
            return sharedFile;
        }

        public void setFileData(SharedClasses.File file, byte[] newData)
        {
            if (file.isEncrypted() == true)
                file.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);
            file.setData(newData);
            file.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
        }

        /// <summary>
        /// Called when the file system has to be disposed at the end of session.The user has to apply changes to the file system and to the shared folder.
        /// </summary>
        public abstract void closeFilesystem();
        /// <summary>
        /// Must throw an exception if login isn't successful.  
        /// This method has the following responsibilities: <br/>
        /// 1)Assigns the root directory to the root reference <br/>
        /// 2)Assigns the shared directory to the sharedFolder reference <br/>
        /// 3)Assigns the upload directory to the uploadFolder reference <br/>
        /// 4)Updates the conents of the shared directory.
        /// </summary>
        /// <exception cref="Exception">When login fails.</exception>
        public abstract void login(SharedClasses.Message.Login loginCreds);

    }
}
