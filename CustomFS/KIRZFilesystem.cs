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
        private int port = 25000;
        private string serverIP = "127.0.0.1";

        private SessionInfo sendDataToServer(byte[] send)
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
                    SessionInfo session = (SessionInfo)bf.Deserialize(ms);
                    return session;
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        public KIRZFilesystem(Credentials creds) : base(creds) { }
        
        public KIRZFilesystem(byte[] encryptionKey, integrityHashAlgorithm hashingAlgorithm, encryptionAlgorithms encryptionAlgorithm, AsymmetricCipherKeyPair keyPair, Credentials loginCreds) : base(encryptionKey, hashingAlgorithm, encryptionAlgorithm, keyPair, loginCreds) { }
        

        /// <summary>
        /// Call this method to retrieve contents of the shared folder from the server.
        /// </summary>
        private void updateSharedFolder()
        {

        }

        /// <summary>
        /// Called when the file system has to be properly disposed at the end of session.
        /// </summary>
        public override void closeFilesystem()
        {
            root.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);

            foreach (SharedClasses.File f in requiresEncryption)
                f.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);

            requiresEncryption.Clear();

            // serialize the file
            byte[] serializedFilesystem;
            BinaryFormatter bf = new BinaryFormatter();
            using(MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, root);
                ms.Position = 0;
                serializedFilesystem = ms.ToArray();
            }
            Array.Clear(encryptionKey, 0, encryptionKey.Length);

            SessionInfo temp = sendDataToServer(serializedFilesystem);
            Console.WriteLine(temp.message);
        }

        public override void login(Credentials loginCreds)
        {
            // use sockets
            SessionInfo session;
            BinaryFormatter binaryFormatter = new BinaryFormatter();
            using (MemoryStream stream = new MemoryStream())
            {
                binaryFormatter.Serialize(stream, loginCreds);
                stream.Position = 0;
                byte[] serializedLoginCreds = stream.ToArray(); // all the data is encrypted in the LoginCredentials ctor, nothing needs to be done manually.
                
                // send the data to server
                session = sendDataToServer(serializedLoginCreds);
                if (session == null)
                    throw new Exception("Login unsuccessful.");
                if (session.cookie == null || session.serializedRoot == null || session.keyDerivationSalt == null)
                {
                    if (session.message != null)
                        throw new Exception(session.message);
                    else
                        throw new Exception("Login unsuccessful.");
                }
            }
            hashingAlgorithm = session.hashingAlgorithm;
            encryptionAlgorithm = session.encryptionAlgorithm;
            cookie = session.cookie;

            byte[] serializedRoot = session.serializedRoot;
            byte[] keyDerivationSalt = session.keyDerivationSalt;

            encryptionKey = CryptoUtilities.scryptKeyDerivation(loginCreds.password, keyDerivationSalt, CryptoUtilities.defaultSymmetricKeySize);

            BinaryFormatter bf = new BinaryFormatter();
            using(MemoryStream ms = new MemoryStream(serializedRoot))
            {
                root = (SharedClasses.File)bf.Deserialize(ms);
            }
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
