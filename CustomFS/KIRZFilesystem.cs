﻿using Org.BouncyCastle.Crypto;
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
            byte[] incomingBuffer = new byte[4096];

            try
            {
                IPAddress ip = IPAddress.Parse(serverIP);
                IPEndPoint endPoint = new IPEndPoint(ip, port);

                Socket socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                socket.Connect(endPoint);

                long messageLength = send.Length;

                // message length will be represented by 8 bytes

                socket.Send(BitConverter.GetBytes(messageLength));
                int bytesSent = socket.Send(send);

                byte[] receivingMessageLen = new byte[8];
                socket.Receive(receivingMessageLen);
                long receivingMessageLength = BitConverter.ToInt64(receivingMessageLen, 0);

                receivedData = new byte[receivingMessageLength];

                int totalBytesReceived = 0;

                while (totalBytesReceived != receivingMessageLength)
                {
                    int bytesReceived = socket.Receive(incomingBuffer);

                    Array.Copy(incomingBuffer, 0, receivedData, totalBytesReceived, bytesReceived);
                    totalBytesReceived += bytesReceived;

                }

                //socket.Receive(receivedData);

                socket.Shutdown(SocketShutdown.Both);
                socket.Close();


                BinaryFormatter bf = new BinaryFormatter();
                using (MemoryStream ms = new MemoryStream(receivedData))
                {
                    return bf.Deserialize(ms);
                }
            }
            catch (Exception e)
            {
                return null;
            }
        }

        public static byte[] serializeObject(object obj)
        {
            BinaryFormatter bf = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream())
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


            List<SharedClasses.File> sharedFolderContents;
            sharedFolder.traverseDirectory(out sharedFolderContents);

            foreach (SharedClasses.File f in sharedFolderContents)
                f.changeParentDir(sharedFolder);
            //f.parentDir = sharedFolder;

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
            if (workingDirectory == sharedFolder)
                throw new Exception("Cannot make files in the shared directory.");

            if (fileName.EndsWith(".txt") == false)
                fileName += ".txt";

            if (workingDirectory.searchDirectory(fileName) != null)
                throw new Exception("File already exists");

            if (workingDirectory == sharedFolder)
                throw new Exception("Cannot create files in the shared directory.");

            SharedClasses.File newFile = new SharedClasses.File(fileName, workingDirectory, false, DateTime.Now);
            newFile.setData(Encoding.UTF8.GetBytes(contents));

            workingDirectory.insertNewFile(newFile);

            // encrypt the parent folder to avoid integrity warnings.Also encrypt the new text file.
            newFile.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
            workingDirectory.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
        }

        public void updateSharedDirectory(SharedClasses.File sharedDir)
        {
            root.deleteFile(sharedFolder);
            //sharedFolder = sharedDir.cloneFile();
            sharedFolder = new SharedClasses.File(sharedFolderName, root, true, DateTime.UtcNow);
            sharedDir.cloneFile(sharedFolder);
            sharedFolder.parentDir = root;

            List<SharedClasses.File> sharedFolderContents;
            sharedFolder.traverseDirectory(out sharedFolderContents);

            foreach (SharedClasses.File f in sharedFolderContents)
                f.changeParentDir(sharedFolder);

            //sharedFolder.parentDir = root;

            // encrypt the file to avoid integrity warnings
            sharedFolder.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm, true);
            root.insertNewFile(sharedFolder);

            // encrypt the root to avoid integrity warnings
            root.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);
        }
    }
}
