using System.Net.Sockets;
using System.Net;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;

namespace tcHAT_Server
{
    internal class Program
    {
        static List<TcpClient> tcpClients = new List<TcpClient>();
        static Dictionary<TcpClient, byte[]> clientKeys = new Dictionary<TcpClient, byte[]>();
        static int count = 0;
        const int maxCount = 30;
        static void Main(string[] args)
        {
            var IPadr = new IPEndPoint(IPAddress.IPv6Any, 6000);
            TcpListener tcpListener = new TcpListener(IPadr);
            tcpListener.Start();
            Console.WriteLine($"Listening on: {IPadr}");

            while (true)
            {
                if (count < maxCount)
                {
                    TcpClient tcpClient = tcpListener.AcceptTcpClient();
                    lock (tcpClients)
                    {
                        tcpClients.Add(tcpClient);
                        count++;
                    }
                    Console.WriteLine("New client connected!");
                    // Handle the client connection in a separate thread
                    Task.Run(() => HandleClient(tcpClient));
                }
                else
                {
                    if (tcpListener.Pending())
                    {
                        TcpClient RejectedClient = tcpListener.AcceptTcpClient();
                        RejectedClient.Close();
                        Console.WriteLine("Reached the max client limit");
                    }
                }
            }
        }

        static void HandleClient(TcpClient tcpClient)
        {
            try
            {
                using (NetworkStream networkStream = tcpClient.GetStream())
                {
                    // Perform ECDH key exchange first
                    byte[] sharedKey = PerformKeyExchange(networkStream);

                    // Store the shared key for this client
                    lock (clientKeys)
                    {
                        clientKeys[tcpClient] = sharedKey;
                    }

                    while (tcpClient.Connected)
                    {
                        // Here mods will land
                        string resourcePath = @"onnx-filter/filter.onnx";

                        byte[] buffer = new byte[1024];
                        int readBytes;
                        while ((readBytes = networkStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            string readText = Encoding.UTF8.GetString(buffer, 0, readBytes);

                            // Use the client-specific shared key for decryption
                            byte[] clientKey;
                            lock (clientKeys)
                            {
                                clientKey = clientKeys[tcpClient];
                            }

                            var deserialisedText = JsonSerializer.Deserialize<MessagePattern>(Decrypt(readText, clientKey));

                            using (var session = new InferenceSession(resourcePath))
                            {
                                var tensor = new DenseTensor<string>(new[] { deserialisedText.Message }, new int[] { 1 });
                                using (var inputOrt = OrtValue.CreateFromStringTensor(tensor))
                                {
                                    var inputs = new List<NamedOnnxValue>
                                    {
                                        NamedOnnxValue.CreateFromTensor("input", tensor)
                                    };
                                    using (var output = session.Run(inputs))
                                    {
                                        var result = output.First();
                                        var tensorResult = result.AsTensor<string>();

                                        var label = tensorResult.First();
                                        var Content = new MessagePattern()
                                        {
                                            Nickname = deserialisedText.Nickname,
                                            Message = deserialisedText.Message
                                        };

                                        // Broadcast to all clients with their respective keys
                                        BroadcastWithKeys(Content, label);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error with client: {ex.Message}");
            }
            finally
            {
                lock (tcpClients)
                {
                    tcpClients.Remove(tcpClient);
                    lock (clientKeys)
                    {
                        clientKeys.Remove(tcpClient);
                    }
                    count--;
                }

                Console.WriteLine("Client disconnected.");
            }
        }

        static byte[] PerformKeyExchange(NetworkStream networkStream)
        {
            // Create a new ECDH key
            using (ECDiffieHellman serverEcdh = ECDiffieHellman.Create())
            {
                // Export the public key to send to the client
                byte[] serverPublicKey = serverEcdh.ExportSubjectPublicKeyInfo();

                // Send the server's public key length and then the key itself
                byte[] keyLengthBytes = BitConverter.GetBytes(serverPublicKey.Length);
                networkStream.Write(keyLengthBytes, 0, keyLengthBytes.Length);
                networkStream.Write(serverPublicKey, 0, serverPublicKey.Length);

                // Receive the client's public key length
                byte[] clientKeyLengthBuffer = new byte[4];
                networkStream.Read(clientKeyLengthBuffer, 0, 4);
                int clientKeyLength = BitConverter.ToInt32(clientKeyLengthBuffer, 0);

                // Receive the client's public key
                byte[] clientPublicKey = new byte[clientKeyLength];
                int bytesRead = 0;
                while (bytesRead < clientKeyLength)
                {
                    int read = networkStream.Read(clientPublicKey, bytesRead, clientKeyLength - bytesRead);
                    if (read == 0)
                        throw new Exception("Connection closed during key exchange");
                    bytesRead += read;
                }

                // Import the client's public key
                using (ECDiffieHellman clientEcdh = ECDiffieHellman.Create())
                {
                    clientEcdh.ImportSubjectPublicKeyInfo(clientPublicKey, out _);

                    // Derive the shared secret
                    byte[] sharedSecret = serverEcdh.DeriveKeyMaterial(clientEcdh.PublicKey);

                    // Use the first 32 bytes (256 bits) of the shared secret as AES key
                    byte[] aesKey = new byte[32];
                    Array.Copy(sharedSecret, aesKey, Math.Min(sharedSecret.Length, 32));

                    Console.WriteLine($"ECDH key exchange completed. Shared key established.");
                    return aesKey;
                }
            }
        }

        static void BroadcastWithKeys(MessagePattern message, string label)
        {
            lock (tcpClients)
            {
                List<TcpClient> disconnectedClients = new List<TcpClient>();

                foreach (TcpClient client in tcpClients)
                {
                    try
                    {
                        if (client.Connected)
                        {
                            // Get the specific key for this client
                            byte[] clientKey;
                            lock (clientKeys)
                            {
                                clientKey = clientKeys[client];
                            }

                            // Encrypt the message with the client's key
                            var Response = new ResponseServerPattern()
                            {
                                Serialised = $"{Encrypt(message, clientKey)}",
                                Label = label
                            };

                            string serializedResponse = JsonSerializer.Serialize(Response);
                            byte[] data = Encoding.UTF8.GetBytes(serializedResponse);

                            NetworkStream ns = client.GetStream();
                            ns.Write(data, 0, data.Length);
                        }
                        else
                        {
                            disconnectedClients.Add(client);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Broadcast error: {ex.Message}");
                        disconnectedClients.Add(client);
                    }
                }

                // Remove disconnected clients
                foreach (var disconnectedClient in disconnectedClients)
                {
                    tcpClients.Remove(disconnectedClient);
                    lock (clientKeys)
                    {
                        clientKeys.Remove(disconnectedClient);
                    }
                }
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