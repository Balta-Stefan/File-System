using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;
using SharedClasses;
using static SharedClasses.CryptoUtilities;

namespace CustomFS
{
    [Serializable]
    class KIRZFilesystem : Filesystem
    {
        // The user will have to manually move the file from the virtual upload folder to whenever he wants (inside virtual file system).

        private string cookie;
        private static int port = 25000;
        private static string serverIP = "127.0.0.1";
        private AsymmetricKeyParameter serverPublicKey;

        public static object sendDataToServer(byte[] send)
        {
            byte[] receivedData = null;

            try
            {
                IPAddress ip = IPAddress.Parse(serverIP);
                IPEndPoint endPoint = new IPEndPoint(ip, port);

                Socket socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                socket.Connect(endPoint);

                int messageLength = send.Length;

                // message length will be represented by 2 bytes
                int upper = messageLength & 0xFF00;
                byte[] messageLenBytes = new byte[2] { (byte)(messageLength & 0xFF), (byte)((messageLength & 0xFF00) >> 8) };
                socket.Send(messageLenBytes);

                int bytesSent = socket.Send(send);

                byte[] receivingMessageLen = new byte[2];
                socket.Receive(receivingMessageLen);
                int receivingMessageLength = receivingMessageLen[0] | (receivingMessageLen[1] << 8);

                receivedData = new byte[receivingMessageLength];
                socket.Receive(receivedData);

                socket.Shutdown(SocketShutdown.Both);
                socket.Close();


                BinaryFormatter bf = new BinaryFormatter();
                using (MemoryStream ms = new MemoryStream(receivedData))
                {
                    return bf.Deserialize(ms);
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static byte[] serializeObject(object obj)
        {
            BinaryFormatter bf = new BinaryFormatter();
            using(MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, obj);
                ms.Position = 0;
                return ms.ToArray();
            }
        }

        public KIRZFilesystem(SharedClasses.Message.Login creds, AsymmetricCipherKeyPair keyPair, AsymmetricKeyParameter serverPublicKey) : base(creds, keyPair)
        {
            this.serverPublicKey = serverPublicKey;
            // shared directory makes lots of problems with the current design.It will be encrypted and then decrypted to get around these problems.
            sharedFolder = new SharedClasses.File(root, sharedFolder, sharedFolderName, true, DateTime.UtcNow);
            sharedFolder.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
            sharedFolder.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);


            SharedClasses.File uploadDir = root.searchDirectory(uploadFolderName);
            if (uploadDir == null)
            {
                uploadDir = new SharedClasses.File(uploadFolderName, root, true, DateTime.Now);
                root.insertNewFile(uploadDir);
                uploadDir.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
            }
            root.insertNewFile(sharedFolder);
            root.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
            uploadFolder = uploadDir;
        }
        
        //public KIRZFilesystem(byte[] encryptionKey, integrityHashAlgorithm hashingAlgorithm, encryptionAlgorithms encryptionAlgorithm, AsymmetricCipherKeyPair keyPair, Credentials loginCreds) : base(encryptionKey, hashingAlgorithm, encryptionAlgorithm, keyPair, loginCreds) { }

        /// <summary>
        /// Called when the file system has to be properly disposed at the end of session.
        /// </summary>
        public override void closeFilesystem()
        {

            foreach (SharedClasses.File f in requiresEncryption)
                f.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);

            requiresEncryption.Clear();

            // serialize the file
            BinaryFormatter bf = new BinaryFormatter();
            

            // log the user out - to do 
            // remove the shared directory from the file system
            root.deleteFile(sharedFolder);
            root.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);


            SharedClasses.Message.LogOut logoutInfo = new SharedClasses.Message.LogOut(serverPublicKey, SharedClasses.File.serializeFile(root), SharedClasses.File.serializeFile(sharedFolder), cookie);
            SharedClasses.Message.LogOut logoutResponse = (SharedClasses.Message.LogOut)sendDataToServer(serializeObject(logoutInfo));

            Array.Clear(encryptionKey, 0, encryptionKey.Length);

            Console.WriteLine(logoutResponse.message);
        }

        public override void login(SharedClasses.Message.Login loginCreds)
        {
            // use sockets
            SharedClasses.Message.LoginReply reply;
            BinaryFormatter binaryFormatter = new BinaryFormatter();
            using (MemoryStream stream = new MemoryStream())
            {
                binaryFormatter.Serialize(stream, loginCreds);
                stream.Position = 0;
                byte[] serializedLoginCreds = stream.ToArray(); // all the data is encrypted in the LoginCredentials ctor, nothing needs to be done manually.

                // send the data to server
                reply = (SharedClasses.Message.LoginReply)sendDataToServer(serializedLoginCreds);
                if (reply.cookie == null)
                    throw new Exception(reply.message);
            }
            hashingAlgorithm = reply.hashAlgorithm;
            encryptionAlgorithm = reply.encryptionAlgorithm;
            cookie = reply.cookie;

            root = SharedClasses.File.deserializeFile(reply.userRoot);
            sharedFolder = SharedClasses.File.deserializeFile(reply.sharedDirectory);

            byte[] keyDerivationSalt = reply.keyDerivationSalt;

            encryptionKey = CryptoUtilities.scryptKeyDerivation(loginCreds.password, keyDerivationSalt, CryptoUtilities.defaultSymmetricKeySize);

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

            SharedClasses.File newFile = new SharedClasses.File(fileName, workingDirectory, false, DateTime.Now);
            newFile.setData(Encoding.UTF8.GetBytes(contents));

            workingDirectory.insertNewFile(newFile);

            // encrypt the parent folder to avoid integrity warnings.Also encrypt the new text file.
            newFile.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
            workingDirectory.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
        }

    }
}
