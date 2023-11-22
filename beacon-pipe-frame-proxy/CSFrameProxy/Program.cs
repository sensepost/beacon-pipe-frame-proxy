namespace CSFrameProxy
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                return;
            }

            string pipeName = args[0];
            string listenPort = args[1];

            FrameProxy proxy = new FrameProxy(pipeName, listenPort, (args.Length == 3) ? true : false);
            proxy.Run();
        }
    }
}
