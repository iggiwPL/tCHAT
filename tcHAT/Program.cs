using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;

namespace tcHAT_Client
{
    internal class Program
    {
        static string nickname = "";
        static string configfile = "/config.json";
        static byte[] sharedKey = null;

        static void Main(string[] args)
        {
            LegalInfo();
            TcpClient tcpClient = new TcpClient();
            Console.WriteLine("Enter the address that you want to connect:");
            try
            {
                var IPadr = new IPEndPoint(IPAddress.Parse(Console.ReadLine()), 6000);
                tcpClient.Connect(IPadr);

                Console.WriteLine($"Connected to server at {IPadr}.");

                if (!File.Exists(Directory.GetCurrentDirectory() + configfile))
                {
                    Console.WriteLine("Type your nickname:");
                    nickname = Console.ReadLine();
                    using (StreamWriter streamWriter = new StreamWriter(File.Create(Directory.GetCurrentDirectory() + configfile)))
                    {
                        var configSave = new Config()
                        {
                            Nickname = nickname
                        };
                        streamWriter.Write(JsonSerializer.Serialize<Config>(configSave));
                    }
                }
                else
                {
                    var deserialisedConfig = JsonSerializer.Deserialize<Config>(File.ReadAllText(Directory.GetCurrentDirectory() + configfile));
                    nickname = deserialisedConfig.Nickname;
                }

                using (NetworkStream networkStream = tcpClient.GetStream())
                {
                    // Perform key exchange before any communication
                    sharedKey = PerformKeyExchange(networkStream);
                    Console.WriteLine("Secure connection established. Type your message:");

                    Task.Run(() => ListenServer(tcpClient, networkStream));
                    while (true)
                    {
                        var message = new MessagePattern
                        {
                            Nickname = nickname,
                            Message = Console.ReadLine()
                        };
                        string serialisedMessage = Encrypt(message, sharedKey);
                        networkStream.Write(Encoding.UTF8.GetBytes(serialisedMessage), 0, serialisedMessage.Length);
                    }
                }
            }
            catch (FormatException fe)
            {
                Console.WriteLine(fe.ToString());
            }
            catch (SocketException se)
            {
                Console.WriteLine(se.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        static byte[] PerformKeyExchange(NetworkStream stream)
        {
            try
            {
                // Create a new ECDH key
                using (ECDiffieHellman clientEcdh = ECDiffieHellman.Create())
                {
                    // Receive the server's public key length
                    byte[] serverKeyLengthBuffer = new byte[4];
                    stream.Read(serverKeyLengthBuffer, 0, 4);
                    int serverKeyLength = BitConverter.ToInt32(serverKeyLengthBuffer, 0);

                    // Receive the server's public key
                    byte[] serverPublicKey = new byte[serverKeyLength];
                    int bytesRead = 0;
                    while (bytesRead < serverKeyLength)
                    {
                        int read = stream.Read(serverPublicKey, bytesRead, serverKeyLength - bytesRead);
                        if (read == 0)
                            throw new Exception("Connection closed during key exchange");
                        bytesRead += read;
                    }

                    // Export the client's public key to send to the server
                    byte[] clientPublicKey = clientEcdh.ExportSubjectPublicKeyInfo();

                    // Send the client's public key length and then the key itself
                    byte[] keyLengthBytes = BitConverter.GetBytes(clientPublicKey.Length);
                    stream.Write(keyLengthBytes, 0, keyLengthBytes.Length);
                    stream.Write(clientPublicKey, 0, clientPublicKey.Length);

                    // Import the server's public key
                    using (ECDiffieHellman serverEcdh = ECDiffieHellman.Create())
                    {
                        serverEcdh.ImportSubjectPublicKeyInfo(serverPublicKey, out _);

                        // Derive the shared secret
                        byte[] sharedSecret = clientEcdh.DeriveKeyMaterial(serverEcdh.PublicKey);

                        // Use the first 32 bytes (256 bits) of the shared secret as AES key
                        byte[] aesKey = new byte[32];
                        Array.Copy(sharedSecret, aesKey, Math.Min(sharedSecret.Length, 32));

                        Console.WriteLine("ECDH key exchange completed successfully.");
                        return aesKey;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Key exchange error: {ex.Message}");
                throw;
            }
        }

        static void LegalInfo()
        {
            Console.WriteLine("LEGAL\nThe public chat is supervised by machine learning filter on server-side and it's not accurate. The filter is only dedicated to english and long messages like e-mails.\nPRESS ANY KEY TO CONTINUE...");
            Console.ReadKey();
            Console.Clear();
        }

        static void ListenServer(TcpClient tcpClient, NetworkStream stream)
        {
            try
            {
                byte[] buffer = new byte[1024];
                int readBytes;

                while ((readBytes = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    // Process only the received bytes
                    string readText = Encoding.UTF8.GetString(buffer, 0, readBytes);
                    var DeserialisedResponse = JsonSerializer.Deserialize<ResponseServerPattern>(readText);
                    var DecryptMessage = JsonSerializer.Deserialize<MessagePattern>(Decrypt(DeserialisedResponse.Serialised, sharedKey));
                    Console.WriteLine($"({DeserialisedResponse.Label}) [{DecryptMessage.Nickname}]: {DecryptMessage.Message}");
                }
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"Socket error: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            finally
            {
                Console.WriteLine("You have been disconnected from server. Server is full or doesn't exist.");
            }
        }

        static string Encrypt(MessagePattern messagePattern, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB; // Keeping ECB as requested
                aes.Key = key;
                ICryptoTransform cryptoTransform = aes.CreateEncryptor(aes.Key, null);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
                    {
                        using (StreamWriter writer = new StreamWriter(cryptoStream))
                        {
                            writer.Write(messagePattern.Message);
                        }
                    }

                    var encrypted = new MessagePattern
                    {
                        Nickname = messagePattern.Nickname,
                        Message = Convert.ToBase64String(ms.ToArray())
                    };
                    return JsonSerializer.Serialize(encrypted);
                }
            }
        }

        static string Decrypt(string encryptedMessage, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB; // Keeping ECB as requested
                aes.Key = key;
                var deserialized = JsonSerializer.Deserialize<MessagePattern>(encryptedMessage);

                if (deserialized == null)
                    throw new InvalidOperationException("Invalid encrypted message format");

                byte[] encryptedBytes = Convert.FromBase64String(deserialized.Message);
                using (MemoryStream ms = new MemoryStream(encryptedBytes))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(cryptoStream))
                        {
                            string decryptedMessage = reader.ReadToEnd();
                            var messageDecryptedSerialised = new MessagePattern()
                            {
                                Nickname = deserialized.Nickname,
                                Message = decryptedMessage
                            };
                            return JsonSerializer.Serialize<MessagePattern>(messageDecryptedSerialised);
                        }
                    }
                }
            }
        }
    }

    public class Config
    {
        public string Nickname { get; set; }
    }

    public class MessagePattern
    {
        public string Nickname { get; set; }
        public string Message { get; set; }
    }

    public class ResponseServerPattern
    {
        public string Serialised { get; set; }
        public string Label { get; set; }
    }
}