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
        static readonly string login_error = "Login error.";
        static readonly string incorrect_credentials = "Incorrect credentials.";
        static readonly string login_successful = "Login successful.";
        static readonly string invalid_certificate = "Invalid certificate.";
        static readonly string certificate_revoked = "Certifikate has been revoked.";
        static readonly string certificate_not_supplied = "Certificate not supplied.";


        private readonly AsymmetricCipherKeyPair keyPair;

        private bool run = true;

        private Dictionary<string, UserInformation> userDatabase = null;
        private Dictionary<string, string> sessions = new Dictionary<string, string>(); // key = cookie, value = user name
        //private Dictionary<string, SharedClasses.File> userRoots = null; // contains root directories of the users (username is the key)
        private Dictionary<BigInteger, UserInformation> serialNumberDatabase;

        public Server(AsymmetricCipherKeyPair keyPair)
        {
            this.keyPair = keyPair;
        }

        void receiveMessages()
        {
            byte[] messageLengthBytes = new byte[2];

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
                        int messageLength = messageLengthBytes[0] | (messageLengthBytes[1] << 8);

                        // allocate a buffer for the incoming data
                        byte[] message = new byte[messageLength];
                        clientSocket.Receive(message);

                        // send the length of the session object to the client
                        byte[] session = determineMessageType(message);
                        messageLengthBytes[0] = (byte)(session.Length & 0xFF);
                        messageLengthBytes[1] = (byte)((session.Length & 0xFF00) >> 8);

                       
                        clientSocket.Send(messageLengthBytes);
                        clientSocket.Send(session);

                        clientSocket.Shutdown(SocketShutdown.Both);
                        clientSocket.Close();
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
        byte[] determineMessageType(byte[] message)
        {
            BinaryFormatter bf = new BinaryFormatter();
            using(MemoryStream ms = new MemoryStream(message))
            {
                try
                {
                    Credentials creds = (Credentials)bf.Deserialize(ms);
                    return loginRegister(creds);
                }
                catch(Exception)
                {
                    // isn't login/registration message
                    try
                    {
                        LogoutData logout = (LogoutData)bf.Deserialize(ms);
                        return userLogout(logout);
                    }
                    catch(Exception)
                    {
                        // isn't logout message
                        return serializeObject(new SessionInfo(login_error, SessionInfo.status.FAILURE));
                    }
                }
            }
        }

        byte[] userLogout(LogoutData data)
        {
            string username;
            if (sessions.TryGetValue(data.cookie, out username) == false)
                return serializeObject(new SessionInfo("error", SessionInfo.status.FAILURE));

            sessions.Remove(data.cookie);

            // change the root
            userDatabase[username].serializedRoot = data.serializedRoot;

            return serializeObject(new SessionInfo("success", SessionInfo.status.SUCCESS));
        }
        byte[] loginRegister(Credentials creds)
        {
            SessionInfo session;
            try
            {
                if (creds.deserialize(keyPair.Private) == false)
                    session = new SessionInfo(login_error, SessionInfo.status.FAILURE);
                else
                {
                    if (creds.type == Credentials.messageType.LOGIN)
                        session = userLogin(creds);
                    else
                        session = registerUser(creds);
                }
            }
            catch(Exception)
            {
                session = new SessionInfo(login_error, SessionInfo.status.FAILURE);
            }

            // serialize the session
            return serializeObject(session);
        }

        private bool validateCertificate(X509Certificate clientCertificate)
        {
            try
            {
                clientCertificate.Verify(keyPair.Public);
                // check common name - to do
               
                // check CRL list - to do
            }
            catch(Exception)
            {
                return false;
            }
            return true;
        }
        SessionInfo userLogin(Credentials creds)
        {
            UserInformation userData;
            if(userDatabase.TryGetValue(creds.username, out userData) == false)
                return new SessionInfo(username_doesnt_exist, SessionInfo.status.FAILURE);

            byte[] hashedPassword = CryptoUtilities.scryptKeyDerivation(creds.password, userData.passwordStorageSalt, UserInformation.hashSize);

            if(compareByteArrays(hashedPassword, userData.hashed_password_with_salt) == false)
                return new SessionInfo(incorrect_credentials, SessionInfo.status.FAILURE);

            if (validateCertificate(creds.decodeClientCertificate()) == false)
                return new SessionInfo(invalid_certificate, SessionInfo.status.FAILURE);

            // create the session
            byte[] cookie = new byte[cookieSize];
            string cookieStr;
            while (true)
            {
                CryptoUtilities.getRandomData(cookie);
                cookieStr = Encoding.UTF8.GetString(cookie);
                if (sessions.ContainsKey(cookieStr) == false)
                    break;
            }

            sessions.Add(cookieStr, creds.username);

            // find the root
            // what happens when there is no root for the new user?
            SessionInfo session = new SessionInfo(userData.serializedRoot, cookieStr, userData.encryptionKeyIV, login_successful, SessionInfo.status.SUCCESS, userData.hashingAlgorithm, userData.encryptionAlgorithm);

            return session;
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
            if(System.IO.File.Exists(userDatabaseFilename) == false)
                userDatabase = new Dictionary<string, UserInformation>();

            BinaryFormatter bf = new BinaryFormatter();
            using(FileStream fs = new FileStream(userDatabaseFilename, System.IO.FileMode.Open, System.IO.FileAccess.Read, FileShare.Read))
            {
                userDatabase = (Dictionary<string, UserInformation>)bf.Deserialize(fs);
            }

            if (System.IO.File.Exists(serialNumberDatabaseFilename) == false)
            {
                serialNumberDatabase = new Dictionary<BigInteger, UserInformation>();
                return;
            }
            using (FileStream fs = new FileStream(serialNumberDatabaseFilename, System.IO.FileMode.Open, System.IO.FileAccess.Read, FileShare.Read))
            {
                serialNumberDatabase = (Dictionary<BigInteger, UserInformation>)bf.Deserialize(fs);
            }

        }
        public void serializeDatabase()
        {
            BinaryFormatter bf = new BinaryFormatter();
            using (FileStream fs = new FileStream(userDatabaseFilename, System.IO.FileMode.Open, System.IO.FileAccess.Read, FileShare.Read))
            {
                bf.Serialize(fs, userDatabase);
            }
            using(FileStream fs = new FileStream(serialNumberDatabaseFilename, System.IO.FileMode.Open, System.IO.FileAccess.Read, FileShare.Read))
            {
                bf.Serialize(fs, serialNumberDatabase);
            }
        }

        private SessionInfo registerUser(Credentials creds)
        {
            if (userDatabase.ContainsKey(creds.username) == true)
                return new SessionInfo(user_exists, SessionInfo.status.FAILURE);

            //UserInformation userLoginCreds = new UserInformation(creds.serializedRoot, creds.password, creds.hashingAlgorithm, creds.encryptionAlgorithm, creds.keyDerivationSalt);

            Pkcs10CertificationRequest csr = creds.csr;
            if (csr == null)
                return new SessionInfo(certificate_not_supplied, SessionInfo.status.FAILURE);

            BigInteger serialNumber;
            do
            {
                serialNumber = BigInteger.Arbitrary(serial_number_size);
            } while (serialNumberDatabase.ContainsKey(serialNumber) == true);

            X509Certificate clientCertificate = CryptoUtilities.sign_CSR(csr, keyPair, serialNumber, serverDN, DateTime.UtcNow, DateTime.UtcNow.AddDays(certificateValidDurationDays));

            UserInformation userLoginCreds = new UserInformation(creds.serializedRoot, creds.password, creds.hashingAlgorithm, creds.encryptionAlgorithm, creds.keyDerivationSalt, clientCertificate);

            serialNumberDatabase.Add(serialNumber, userLoginCreds);
            userDatabase.Add(creds.username, userLoginCreds);

            byte[] serializedClientCertificate = serializeObject(clientCertificate);

            return new SessionInfo(registration_successful, SessionInfo.status.SUCCESS, serializedClientCertificate);
        }
        static void Main(string[] args)
        {
            // get key pair
            AsymmetricCipherKeyPair CAkeyPair = CryptoUtilities.load_keypair_from_file("CAkey.pem");
            AsymmetricCipherKeyPair clientKeyPair = CryptoUtilities.generate_RSA_key_pair(2048);
            /*Server obj = new Server(keyPair);

            obj.deserializeDatabase();

            obj.receiveMessages();*/


            Pkcs10CertificationRequest req = CryptoUtilities.generateCSR(clientKeyPair, "Ime", "ETF", "RI", "RS", "BA");
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
             
            Console.ReadLine();
        }
    }
}
