using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace MiniMiner
{
    class Utils
    {
        public static byte[] ToBytes(string input)
        {
            byte[] bytes = new byte[input.Length / 2];
            for (int i = 0, j = 0; i < input.Length; j++, i += 2)
                bytes[j] = byte.Parse(input.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);

            return bytes;
        }

        public static string ToString(byte[] input)
        {
            string result = "";
            foreach (byte b in input)
                result += b.ToString("x2");

            return result;
        }

        public static string ToString(uint value)
        {
            string result = "";
            foreach (byte b in BitConverter.GetBytes(value))
                result += b.ToString("x2");

            return result;
        }

        public static string EndianFlip32BitChunks(string input)
        {
            //32 bits = 4*4 bytes = 4*4*2 chars
            string result = "";
            for (int i = 0; i < input.Length; i += 8)
                for (int j = 0; j < 8; j += 2)
                {
                    //append byte (2 chars)
                    result += input[i - j + 6];
                    result += input[i - j + 7];
                }
            return result;        
        }

        public static string RemovePadding(string input)
        {
            //payload length: final 64 bits in big-endian - 0x0000000000000280 = 640 bits = 80 bytes = 160 chars
            return input.Substring(0, 160);
        }

        public static string AddPadding(string input)
        {
            //add the padding to the payload. It never changes.
            return input + "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000";
        }
    }

    class Work
    {
        public Work(byte[] data)
        {
            Data = data;
            Current = (byte[])data.Clone();
            _nonceOffset = Data.Length - 4;
            _ticks = DateTime.Now.Ticks;
            _hasher = new SHA256Managed();

        }
        private SHA256Managed _hasher;
        private long _ticks;
        private long _nonceOffset;
        public byte[] Data;
        public byte[] Current;

        internal bool FindShare(ref uint nonce, uint batchSize)
        {
            for(;batchSize > 0; batchSize--)
            {
                BitConverter.GetBytes(nonce).CopyTo(Current, _nonceOffset);
                byte[] doubleHash = Sha256(Sha256(Current));

                //count trailing bytes that are zero
                int zeroBytes = 0;
                for (int i = 31; i >= 28; i--, zeroBytes++)
                    if(doubleHash[i] > 0)
                        break;

                //standard share difficulty matched! (target:ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000)
                if(zeroBytes == 4)
                    return true;

                //increase
                if(++nonce == uint.MaxValue)
                    nonce = 0;
            }
            return false;
        }

        private byte[] Sha256(byte[] input)
        {
            byte[] crypto = _hasher.ComputeHash(input, 0, input.Length);
            return crypto;
        }

        public byte[] Hash
        {
            get { return Sha256(Sha256(Current)); }
        }

        public long Age 
        {
            get { return DateTime.Now.Ticks - _ticks; }
        }
    }

    class Pool
    {
        public Uri Url;
        public string User;
        public string Password;

        public Pool(string login)
        {
            int urlStart = login.IndexOf('@');
            int passwordStart = login.IndexOf(':');
            string user = login.Substring(0, passwordStart);
            string password = login.Substring(passwordStart + 1, urlStart - passwordStart - 1);
            string url = "http://"+login.Substring(urlStart + 1);
            Url = new Uri(url);
            User = user;
            Password = password;
        }

        private string InvokeMethod(string method, string paramString = null)
        {
            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(Url);
            webRequest.Credentials = new NetworkCredential(User, Password);
            webRequest.ContentType = "application/json-rpc";
            webRequest.Method = "POST";

            string jsonParam = (paramString != null) ? "\"" + paramString + "\"" : "";
            string request = "{\"id\": 0, \"method\": \"" + method + "\", \"params\": [" + jsonParam + "]}";

            // serialize json for the request
            byte[] byteArray = Encoding.UTF8.GetBytes(request);
            webRequest.ContentLength = byteArray.Length;
            using (Stream dataStream = webRequest.GetRequestStream())
                dataStream.Write(byteArray, 0, byteArray.Length);

            string reply = "";
            using (WebResponse webResponse = webRequest.GetResponse())
            using (Stream str = webResponse.GetResponseStream())
            using (StreamReader reader = new StreamReader(str))
                reply = reader.ReadToEnd();

            return reply;
        }
        
        public Work GetWork(bool silent = false)
        {
            return new Work(ParseData(InvokeMethod("getwork")));
        }

        private byte[] ParseData(string json)
        {
            Match match = Regex.Match(json, "\"data\": \"([A-Fa-f0-9]+)");
            if (match.Success)
            {
                string data = Utils.RemovePadding(match.Groups[1].Value);
                data = Utils.EndianFlip32BitChunks(data);
                return Utils.ToBytes(data);
            }
            throw new Exception("Didn't find valid 'data' in Server Response");
        }

        public bool SendShare(byte[] share)
        {
            string data = Utils.EndianFlip32BitChunks(Utils.ToString(share));
            string paddedData = Utils.AddPadding(data);
            string jsonReply = InvokeMethod("getwork", paddedData);
            Match match = Regex.Match(jsonReply, "\"result\": true");
            return match.Success;
        }
    }

    class Program
    {
        static Pool _pool = null;
        static Work _work = null;
        static uint _nonce = 0;
        static long _maxAgeTicks = 20000 * TimeSpan.TicksPerMillisecond;
        static uint _batchSize = 100000;

        static void Main(string[] args)
        {
            while (true)
            {
                try
                {
                    _pool = SelectPool();
                    _work = GetWork();
                    while (true)
                    {
                        if (_work == null || _work.Age > _maxAgeTicks)
                            _work = GetWork();

                        if (_work.FindShare(ref _nonce, _batchSize))
                        {
                            SendShare(_work.Current);
                            _work = null;
                        }
                        else
                            PrintCurrentState();
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine();
                    Console.Write("ERROR: ");
                    Console.WriteLine(e.Message);
                }
                Console.WriteLine();
                Console.Write("Hit 'Enter' to try again...");
                Console.ReadLine();
            }
        }


        private static void ClearConsole()
        {
            Console.Clear();
            Console.WriteLine("*****************************");
            Console.WriteLine("*** Minimal Bitcoin Miner ***");
            Console.WriteLine("*****************************");
            Console.WriteLine();
        }

        private static Pool SelectPool()
        {
            ClearConsole();
            Print("Chose a Mining Pool 'user:password@url:port' or leave empty to skip.");
            Console.Write("Select Pool: ");
            string login = ReadLineDefault("lithander_2:foo@btcguild.com:8332");
            return new Pool(login);
        }

        private static Work GetWork()
        {
            ClearConsole();
            Print("Requesting Work from Pool...");
            Print("Server URL: " + _pool.Url.ToString());
            Print("User: " + _pool.User);
            Print("Password: " + _pool.Password);
            return _pool.GetWork();
        }

        private static void SendShare(byte[] share)
        {
            ClearConsole();
            Print("*** Found Valid Share ***");
            Print("Share: " + Utils.ToString(_work.Current));
            Print("Nonce: " + Utils.ToString(_nonce));
            Print("Hash: " + Utils.ToString(_work.Hash));
            Print("Sending Share to Pool...");
            if (_pool.SendShare(share))
                Print("Server accepted the Share!");
            else
                Print("Server declined the Share!");

            Console.Write("Hit 'Enter' to continue...");
            Console.ReadLine();
        }

        private static DateTime _lastPrint = DateTime.Now;
        private static void PrintCurrentState()
        {
            ClearConsole();
            Print("Data: " + Utils.ToString(_work.Data));
            string current = Utils.ToString(_nonce);
            string max = Utils.ToString(uint.MaxValue);
            double progress = ((double)_nonce / uint.MaxValue) * 100;
            Print("Nonce: " + current + "/" + max + " " + progress.ToString("F2") + "%");
            Print("Hash: " + Utils.ToString(_work.Hash));
            TimeSpan span = DateTime.Now - _lastPrint;
            Print("Speed: " + (int)(((_batchSize) / 1000) / span.TotalSeconds) + "Kh/s"); 
            _lastPrint = DateTime.Now;
        }

        private static void Print(string msg)
        {
            Console.WriteLine(msg);
            Console.WriteLine();
        }

        private static string ReadLineDefault(string defaultValue)
        {
            //Allow Console.ReadLine with a default value
            string userInput = Console.ReadLine();
            Console.WriteLine();
            if (userInput == "")
                return defaultValue;
            else
                return userInput;
        }
    }
}
