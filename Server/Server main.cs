using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using SharedClasses;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading;

namespace Server
{
    class Server
    {
        /// <summary>
        /// Protocol:
        /// First, a 2 byte byte array is sent such that: array[0] = lower byte, array[1] = upper byte which specifies length (in bytes) of the payload.
        /// Finally, the payload is sent.
        /// </summary>
        private static readonly string userDatabaseFilename = "Database.bin";
        private static readonly string serialNumberDatabaseFilename = "Serial number database.bin";
        private static readonly string sharedDirectoryFilename = "Shared directory.bin";
        private static readonly string CRLfilename = "CRL.bin";

        //static readonly string CAfilename = "CAcert.pem";
        static readonly int cookieSize = 16; // 128 bits long
        static readonly int port = 25000;
        static readonly string IP = "127.0.0.1";
        static readonly int max_number_of_connections = 15;
        static readonly int serial_number_size = 64; // in bits
        static readonly string serverDN = "CN=KIRZ CA, O=ETF, OU=Racunarstvo i informatika, ST=RS, C=BiH";
        static readonly int certificateValidDurationDays = 365;


        // messages
        static readonly string registration_successful = "Registration successful.";
        static readonly string user_exists = "Username already exists.";
        static readonly string username_doesnt_exist = "Such username doesn't exist.";
        static readonly string login_successful = "Login successful.";
        static readonly string login_error = "Login error.";
        static readonly string incorrect_credentials = "Incorrect credentials.";
        static readonly string invalid_certificate = "Invalid certificate.";
        static readonly string certificate_revoked = "Certificate has been revoked.";
        static readonly string certificate_not_supplied = "Certificate not supplied.";
        static readonly string logout_error = "User not logged in.";
        static readonly string logout_successful = "Logout successful";
        static readonly string uknown_message = "Unknown message";
        static readonly string invalid_password = "Invalid password.";

        private readonly AsymmetricCipherKeyPair keyPair;
        private SharedClasses.File sharedDirectory;

        public bool run = true;


        private Dictionary<string, UserInformation> userDatabase = null;
        private Dictionary<string, string> sessions = new Dictionary<string, string>(); // key = cookie, value = user name
        //private Dictionary<string, SharedClasses.File> userRoots = null; // contains root directories of the users (username is the key)
        private Dictionary<BigInteger, UserInformation> serialNumberDatabase;
        private Dictionary<BigInteger, bool> CRL;

        public Server(AsymmetricCipherKeyPair keyPair)
        {
            this.keyPair = keyPair;
        }


        void receiveMessages()
        {
            byte[] messageLengthBytes = new byte[8];
            byte[] incomingBuffer = new byte[4096];

            try
            {
                IPAddress ipAddress = IPAddress.Parse(IP);
                IPEndPoint localEndPoint = new IPEndPoint(ipAddress, port);

                Socket listener = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                
                listener.Bind(localEndPoint);
                listener.Listen(max_number_of_connections);
                while (run)
                {
                    try
                    {
                        Console.WriteLine("Waiting for a connection...");

                        Socket clientSocket = listener.Accept();
                        Console.WriteLine("Server has received a connection.");

                        // obtain the message length represented by 2 bytes
                        clientSocket.Receive(messageLengthBytes);

                        long messageLength = BitConverter.ToInt64(messageLengthBytes, 0);

                        // allocate a buffer for the incoming data
                        // the problem is that the Receive method won't block until all of the data is received.It might stop earlier.


                        byte[] message = new byte[messageLength];
                        //int bytesReceived = clientSocket.Receive(message);
                        int totalBytesReceived = 0;

                        while(totalBytesReceived != messageLength)
                        {
                            int bytesReceived = clientSocket.Receive(incomingBuffer);
                            Array.Copy(incomingBuffer, 0, message, totalBytesReceived, bytesReceived);
                            totalBytesReceived += bytesReceived;
                        }

                        // send the length of the session object to the client
                        byte[] session = determineMessageType(message);
                        //messageLengthBytes[0] = (byte)(session.Length & 0xFF);
                        //messageLengthBytes[1] = (byte)((session.Length & 0xFF00) >> 8);

                       
                        clientSocket.Send(BitConverter.GetBytes((long)(session.Length)));
                        clientSocket.Send(session);

                        clientSocket.Shutdown(SocketShutdown.Both);
                        clientSocket.Close();
                    }
                    catch(ThreadAbortException)
                    {
                        return;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                }
              
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
       
        private byte[] serializeObject(object obj)
        {
            BinaryFormatter bf = new BinaryFormatter();
            using(MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, obj);
                ms.Position = 0;
                return ms.ToArray();
            }
        }

        private object deserializeObject(byte[] obj)
        {
            BinaryFormatter bf = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream(obj))
            {
                return bf.Deserialize(ms);
            }
        }
        byte[] determineMessageType(byte[] message)
        {
            BinaryFormatter bf = new BinaryFormatter();
            using(MemoryStream ms = new MemoryStream(message))
            {
                object deserialized = bf.Deserialize(ms);
                if(deserialized is Message == false)
                    return serializeObject(new Message(uknown_message, keyPair.Private));

                Message msg = (Message)((Message)deserialized).decrypt(keyPair.Private);

                if (deserialized is SharedClasses.Message.Login)
                    return userLogin((SharedClasses.Message.Login)msg);
                else if (deserialized is SharedClasses.Message.Registration)
                    return userRegistration((SharedClasses.Message.Registration)msg);

                else if (deserialized is SharedClasses.Message.LogOut)
                    return userLogout((SharedClasses.Message.LogOut)msg);
                else if (deserialized is SharedClasses.Message.PublicKeyRequest)
                    return getPublicKey((SharedClasses.Message.PublicKeyRequest)msg);
                else if (deserialized is SharedClasses.Message.ShareFile)
                    return shareFile((SharedClasses.Message.ShareFile)msg);
                else
                    return serializeObject(new Message(uknown_message, keyPair.Private));
            }
        }

        byte[] getPublicKey(SharedClasses.Message.PublicKeyRequest request)
        {
            UserInformation userInfo;
            if (userDatabase.TryGetValue(request.userName, out userInfo) == false)
                return serializeObject(new SharedClasses.Message.PublicKeyRequest(keyPair.Private, null, username_doesnt_exist));

            AsymmetricKeyParameter userKey = userInfo.decodeCertificate().GetPublicKey();

            return serializeObject(new SharedClasses.Message.PublicKeyRequest(keyPair.Private, userKey, "Success"));
        }

        byte[] userRegistration(SharedClasses.Message.Registration registrationInfo)
        {
            if (userDatabase.ContainsKey(registrationInfo.username) == true)
                return serializeObject(new Message.RegistrationReply(user_exists, keyPair.Private));

            // sign the certificate
            X509Certificate clientCert = CryptoUtilities.sign_CSR(registrationInfo.decodePEMcsr(), keyPair, BigInteger.Arbitrary(serial_number_size), serverDN, DateTime.UtcNow, DateTime.UtcNow.AddDays(certificateValidDurationDays));
            UserInformation userInfo = new UserInformation(registrationInfo.username, registrationInfo.userRoot, registrationInfo.password, registrationInfo.hashAlgorithm, registrationInfo.encryptionAlgorithm, registrationInfo.keyDerivationSalt, clientCert);

            // store the user into the database
            userDatabase.Add(registrationInfo.username, userInfo);

            return serializeObject(new Message.RegistrationReply(registration_successful, keyPair.Private, clientCert));
        }

        byte[] shareFile(SharedClasses.Message.ShareFile share)
        {
            SharedClasses.File alreadyExists = sharedDirectory.searchDirectory(share.fileToShare.name);
            if (alreadyExists != null)
                sharedDirectory.deleteFile(alreadyExists);

            sharedDirectory.insertNewFile(share.fileToShare);
            return serializeObject(new Message.ShareFile(sharedDirectory, keyPair.Private));

            //return serializeObject(new Message("success", keyPair.Private));
        }

        byte[] userLogin(SharedClasses.Message.Login loginInfo)
        {
            UserInformation userInfo;
            if (userDatabase.TryGetValue(loginInfo.username, out userInfo) == false)
                return serializeObject(new Message.LoginReply(username_doesnt_exist, keyPair.Private));

            if (validateCertificate(loginInfo.decodeCertificate(), userInfo) == false)
                return serializeObject(new Message.LoginReply(invalid_certificate, keyPair.Private));

            byte[] passwordHash = CryptoUtilities.scryptKeyDerivation(loginInfo.password, userInfo.passwordStorageSalt, UserInformation.hashSize);

            if (compareByteArrays(passwordHash, userInfo.hashed_password_with_salt) == false)
                return serializeObject(new Message.LoginReply(invalid_password, keyPair.Private));

            // create the session
            byte[] cookie = new byte[cookieSize];
            string cookieStr;

            do
            {
                CryptoUtilities.getRandomData(cookie);
                cookieStr = Encoding.UTF8.GetString(cookie);
            } while (sessions.ContainsKey(cookieStr) == true);

            sessions.Add(cookieStr, loginInfo.username);

            Message.LoginReply loginReply = new Message.LoginReply(cookieStr, login_successful, SharedClasses.File.serializeFile(sharedDirectory), userInfo.userRoot, userInfo.symmetricEncryptionKeyDerivationSalt, keyPair.Private, userInfo.hashingAlgorithm, userInfo.encryptionAlgorithm);
            return serializeObject(loginReply);
        }

        byte[] userLogout(SharedClasses.Message.LogOut logoutInfo)
        {
            string username;

            if (sessions.TryGetValue(logoutInfo.cookie, out username) == false)
                return serializeObject(new SharedClasses.Message.LogOut(logout_error, keyPair.Private));
            sessions.Remove(logoutInfo.cookie);

            UserInformation userInfo = userDatabase[username];
            userInfo.userRoot = logoutInfo.userRoot;
            sharedDirectory = SharedClasses.File.deserializeFile(logoutInfo.sharedDirectory);

            return serializeObject(new SharedClasses.Message.LogOut(logout_successful, keyPair.Private));
        }

        private bool validateCertificate(X509Certificate clientCertificate, UserInformation userInfo)
        {
            try
            {
                clientCertificate.Verify(keyPair.Public);
                // check if the given certificate belongs to the given user
                if (clientCertificate.Equals(userInfo.decodeCertificate()) == false)
                    return false;
                // check common name - to do

                if (CRL.ContainsKey(clientCertificate.SerialNumber) == true)
                    return false;
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }


        private bool compareByteArrays(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
                return false;
            else if ((first == null && second != null) || (first != null && second == null))
                return false;
            else if (first != null && second != null)
            {
                for (int i = 0; i < first.Length; i++)
                {
                    if (first[i] != second[i])
                        return false;
                }
            }
            return true;
        }
       
        public void deserializeDatabase()
        {
            BinaryFormatter bf = new BinaryFormatter();
            if (System.IO.File.Exists(userDatabaseFilename) == false)
                userDatabase = new Dictionary<string, UserInformation>();
            else
            {
                using (FileStream fs = new FileStream(userDatabaseFilename, System.IO.FileMode.Open, System.IO.FileAccess.Read, FileShare.Read))
                {
                    userDatabase = (Dictionary <string, UserInformation>)(bf.Deserialize(fs));
                }
            }

            if (System.IO.File.Exists(serialNumberDatabaseFilename) == false)
                serialNumberDatabase = new Dictionary<BigInteger, UserInformation>();
            else
            {
                using (FileStream fs = new FileStream(serialNumberDatabaseFilename, System.IO.FileMode.Open, System.IO.FileAccess.Read, FileShare.Read))
                {
                    serialNumberDatabase = (Dictionary<BigInteger, UserInformation>)bf.Deserialize(fs);
                }
            }

            // obtain the shared dir
            if (System.IO.File.Exists(sharedDirectoryFilename) == false)
                sharedDirectory = new SharedClasses.File("shared", null, true, DateTime.UtcNow);
            else
            {
                using (FileStream fs = new FileStream(sharedDirectoryFilename, System.IO.FileMode.Open, System.IO.FileAccess.Read, FileShare.Read))
                {
                    sharedDirectory = (SharedClasses.File)bf.Deserialize(fs);
                }
            }

            if (System.IO.File.Exists(CRLfilename) == false)
                CRL = new Dictionary<BigInteger, bool>();
            else
            {
                using (FileStream fs = new FileStream(CRLfilename, System.IO.FileMode.Open, System.IO.FileAccess.Read, FileShare.Read))
                {
                    CRL = (Dictionary<BigInteger, bool>)bf.Deserialize(fs);
                }
            }
        }
        public void serializeDatabase()
        {
          
            BinaryFormatter bf = new BinaryFormatter();
            using (FileStream fs = new FileStream(userDatabaseFilename, System.IO.FileMode.Create, System.IO.FileAccess.Write, FileShare.Read))
            {
                bf.Serialize(fs, userDatabase);
            }
            using (FileStream fs = new FileStream(serialNumberDatabaseFilename, System.IO.FileMode.Create, System.IO.FileAccess.Write, FileShare.Read))
            {
                bf.Serialize(fs, serialNumberDatabase);
            }
            using (FileStream fs = new FileStream(sharedDirectoryFilename, System.IO.FileMode.Create, System.IO.FileAccess.Write, FileShare.Read))
            {
                bf.Serialize(fs, sharedDirectory);
            }
            using (FileStream fs = new FileStream(sharedDirectoryFilename, System.IO.FileMode.Create, System.IO.FileAccess.Write, FileShare.Read))
            {
                bf.Serialize(fs, sharedDirectory);
            }
            
            using (FileStream fs = new FileStream(CRLfilename, System.IO.FileMode.Create, System.IO.FileAccess.Write, FileShare.Read))
            {
                bf.Serialize(fs, CRL);
            }
        }
    
        void stop()
        {
            run = false;
        }

        void revokeCert()
        {
            Console.WriteLine("Enter username.");
            string username = Console.ReadLine();

            UserInformation userInfo;
            if(userDatabase.TryGetValue(username, out userInfo) == false)
            {
                Console.WriteLine("User doesn't exist.");
                return;
            }

            CRL.Add(userInfo.decodeCertificate().SerialNumber, true);
        }
        static void Main(string[] args)
        {
            // get key pair
            //AsymmetricCipherKeyPair CAkeyPair = CryptoUtilities.load_keypair_from_file("CAkey.pem");
            //AsymmetricCipherKeyPair clientKeyPair = CryptoUtilities.generate_RSA_key_pair(2048);
            AsymmetricCipherKeyPair keyPair;
            try
            {
                keyPair = CryptoUtilities.load_keypair_from_file("CAkey.pem");
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
                Console.ReadLine();
                return;
            }
            Server obj = new Server(keyPair);

            obj.deserializeDatabase();

            Thread thread = new Thread(obj.receiveMessages);
            //obj.receiveMessages();
            thread.Start();

            bool runLoop = true;
            while(runLoop)
            {
                Console.WriteLine("1)Stop");
                Console.WriteLine("2)Revoke certificate");

                string choice = Console.ReadLine();
                int choiceNum = 0;
                try
                {
                    choiceNum = Int32.Parse(choice);
                }
                catch(Exception)
                {
                    Console.WriteLine("Incorrect input.");
                    continue;
                }

                switch(choiceNum)
                {
                    case 1:
                        obj.stop();
                        runLoop = false;
                        break;
                    case 2:
                        obj.revokeCert();
                        break;
                    default:
                        Console.WriteLine("Incorrect input.");
                        break;
                }
            }
           
            thread.Abort();
            obj.serializeDatabase();
            Console.ReadLine();
            Console.WriteLine(thread.ThreadState);

            /*Pkcs10CertificationRequest req = CryptoUtilities.generateCSR(clientKeyPair, "Ime", "ETF", "RI", "RS", "BA");
            string subjectDN = req.GetCertificationRequestInfo().Subject.ToString();
            string[] data = subjectDN.Split(',');
            string commonName = null, orgName = null, departmentName = null, stateName = null, countryName = null;
            foreach (string s in data)
                s.Trim();
            foreach (string s in data)
            {
                if (s.Contains("CN="))
                    commonName = s.Substring(3);
                else if (s.Contains("O="))
                    orgName = s.Substring(2);
                else if (s.Contains("OU="))
                    departmentName = s.Substring(3);
                else if (s.Contains("ST="))
                    stateName = s.Substring(3);
                else if (s.Contains("C="))
                    countryName = s.Substring(2);
            }
            Console.WriteLine(commonName);
            Console.WriteLine(orgName);
            Console.WriteLine(departmentName);
            Console.WriteLine(stateName);
            Console.WriteLine(countryName);

            

            X509Certificate cert = CryptoUtilities.sign_CSR(req, CAkeyPair, BigInteger.Arbitrary(64), serverDN, DateTime.UtcNow, DateTime.Now.AddDays(365));
            Console.WriteLine(cert.ToString());
            try
            {
                cert.Verify(CAkeyPair.Public);
                Console.WriteLine("CA did sign this cert.");
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
            CryptoUtilities.dumpToPEM(cert, "clientCertificate.pem");
             
            Console.ReadLine();*/
        }
    }
}
