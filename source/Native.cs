using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ClaudeRecovery {
    internal sealed class KernelHandle : SafeHandleZeroOrMinusOneIsInvalid {
        public KernelHandle() : base(true) { }
        public KernelHandle(IntPtr value) : base(true) { SetHandle(value); }
        protected override bool ReleaseHandle() { return Native.CloseHandle(handle); }
    }

    internal sealed class ProcessIdentity {
        public int Pid;
        public long CreatedFileTime;
        public string ImagePath;
        public int SessionId;
        public bool Critical;
    }

    internal static class Native {
        [StructLayout(LayoutKind.Sequential)] internal struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)] internal struct ObjectAttributes { public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
        [StructLayout(LayoutKind.Sequential)] struct DirectoryInformation { public UnicodeString Name, TypeName; }
        [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low, High; public long Value { get { return ((long)High << 32) | Low; } } }
        [DllImport("ntdll.dll")] static extern int NtOpenDirectoryObject(out IntPtr handle, uint access, ref ObjectAttributes attributes);
        [DllImport("ntdll.dll")] static extern int NtQueryDirectoryObject(IntPtr handle, IntPtr buffer, uint length, [MarshalAs(UnmanagedType.U1)] bool single, [MarshalAs(UnmanagedType.U1)] bool restart, ref uint context, out uint returned);
        [DllImport("ntdll.dll")] static extern int NtOpenJobObject(out IntPtr handle, uint access, ref ObjectAttributes attributes);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(KernelHandle process, out FileTime created, out FileTime exited, out FileTime kernel, out FileTime user);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageName(KernelHandle process, uint flags, StringBuilder path, ref uint length);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessCritical(KernelHandle process, out bool critical);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool ProcessIdToSessionId(uint pid, out uint session);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(KernelHandle job, int info, IntPtr buffer, uint length, out uint returned);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(KernelHandle process, KernelHandle job, out bool result);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(KernelHandle process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(KernelHandle process, uint milliseconds);

        sealed class ObjectName : IDisposable {
            IntPtr text, unicode;
            public ObjectAttributes Attributes;
            public ObjectName(string name) {
                text=Marshal.StringToHGlobalUni(name);
                unicode=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(new UnicodeString { Length=checked((ushort)(name.Length*2)), MaximumLength=checked((ushort)((name.Length+1)*2)), Buffer=text },unicode,false);
                Attributes=new ObjectAttributes { Length=Marshal.SizeOf(typeof(ObjectAttributes)), ObjectName=unicode, Attributes=0x40 };
            }
            public void Dispose() { Marshal.FreeHGlobal(unicode); Marshal.FreeHGlobal(text); }
        }

        public static List<string> EnumerateClaudeJobs() {
            var names=new List<string>();
            IntPtr raw;
            using(var name=new ObjectName("\\")) {
                int status=NtOpenDirectoryObject(out raw,1,ref name.Attributes);
                if(status<0) throw new InvalidOperationException("컨테이너 목록 조회 실패: 0x"+status.ToString("X8"));
            }
            using(var directory=new KernelHandle(raw)) {
                IntPtr buffer=Marshal.AllocHGlobal(65536);
                try {
                    uint context=0, returned;
                    bool restart=true;
                    for(int i=0;i<100000;i++) {
                        int status=NtQueryDirectoryObject(directory.DangerousGetHandle(),buffer,65536,true,restart,ref context,out returned);
                        restart=false;
                        if(status==unchecked((int)0x8000001A)) return names;
                        if(status<0) throw new InvalidOperationException("컨테이너 목록 일부를 읽지 못했습니다: 0x"+status.ToString("X8"));
                        var entry=(DirectoryInformation)Marshal.PtrToStructure(buffer,typeof(DirectoryInformation));
                        string item=Marshal.PtrToStringUni(entry.Name.Buffer,entry.Name.Length/2);
                        string type=Marshal.PtrToStringUni(entry.TypeName.Buffer,entry.TypeName.Length/2);
                        if(type=="Job" && item.StartsWith("Container_Claude_",StringComparison.Ordinal)) names.Add("\\"+item);
                    }
                    throw new InvalidOperationException("컨테이너 목록 조회 한도를 초과했습니다.");
                } finally { Marshal.FreeHGlobal(buffer); }
            }
        }

        public static KernelHandle OpenJob(string name) {
            IntPtr raw;
            using(var objectName=new ObjectName(name)) {
                int status=NtOpenJobObject(out raw,4,ref objectName.Attributes);
                if(status<0) throw new InvalidOperationException("컨테이너 접근 실패 (관리자 권한 필요 가능): 0x"+status.ToString("X8"));
            }
            return new KernelHandle(raw);
        }

        public static List<int> Members(KernelHandle job) {
            const int size=1024*1024;
            IntPtr buffer=Marshal.AllocHGlobal(size);
            try {
                uint returned;
                if(!QueryInformationJobObject(job,3,buffer,size,out returned)) throw new Win32Exception(Marshal.GetLastWin32Error(),"소속 프로세스 조회 실패");
                int assigned=Marshal.ReadInt32(buffer,0), count=Marshal.ReadInt32(buffer,4);
                int capacity=(size-8)/IntPtr.Size;
                if(assigned<0 || count<0 || assigned>capacity || count>capacity) throw new InvalidOperationException("프로세스 목록이 버퍼 범위를 초과했습니다. 다시 검사하세요.");
                // NumberOfProcessIdsInList defines the valid entries returned by this call.
                // During process exit Windows can transiently report assigned > returned count;
                // treating that as corruption causes false failures after successful cleanup.
                var ids=new List<int>();
                for(int i=0;i<count;i++) ids.Add(checked((int)Marshal.ReadIntPtr(buffer,8+i*IntPtr.Size).ToInt64()));
                return ids;
            } finally { Marshal.FreeHGlobal(buffer); }
        }

        public static KernelHandle OpenProcessForInspection(int pid, bool terminate) {
            uint access=0x00101000u | (terminate ? 1u : 0u);
            var handle=new KernelHandle(OpenProcess(access,false,(uint)pid));
            if(handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error,"프로세스 접근 실패 (PID "+pid+")"); }
            return handle;
        }

        public static ProcessIdentity Identity(KernelHandle process, int pid) {
            FileTime created, exited, kernel, user;
            if(!GetProcessTimes(process,out created,out exited,out kernel,out user)) throw new Win32Exception(Marshal.GetLastWin32Error());
            uint alive=WaitForSingleObject(process,0);
            if(alive==0) throw new InvalidOperationException("이미 종료된 프로세스입니다.");
            if(alive!=258) throw new Win32Exception(Marshal.GetLastWin32Error(),"프로세스 실행 상태 조회 실패");
            var path=new StringBuilder(32768); uint length=(uint)path.Capacity;
            if(!QueryFullProcessImageName(process,0,path,ref length)) throw new Win32Exception(Marshal.GetLastWin32Error());
            bool critical; uint session;
            if(!IsProcessCritical(process,out critical) || !ProcessIdToSessionId((uint)pid,out session)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return new ProcessIdentity { Pid=pid, CreatedFileTime=created.Value, ImagePath=path.ToString(), SessionId=(int)session, Critical=critical };
        }

        // The same open process handle is used for identity, membership, and termination.
        // This prevents PID reuse between validation and TerminateProcess.
        public static string TerminateVerified(KernelHandle job, ProcessIdentity expected, int allowedSession) {
            if(expected.Pid<=4 || expected.Pid==System.Diagnostics.Process.GetCurrentProcess().Id) throw new InvalidOperationException("보호된 프로세스입니다.");
            using(var process=OpenProcessForInspection(expected.Pid,true)) {
                var live=Identity(process,expected.Pid);
                if(live.CreatedFileTime!=expected.CreatedFileTime || !String.Equals(live.ImagePath,expected.ImagePath,StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("PID의 시작 시각 또는 실행 파일이 바뀌어 종료하지 않았습니다.");
                if(live.Critical || live.SessionId!=allowedSession) throw new InvalidOperationException("시스템 또는 다른 로그인 세션의 프로세스는 종료할 수 없습니다.");
                bool belongs;
                if(!IsProcessInJob(process,job,out belongs)) throw new Win32Exception(Marshal.GetLastWin32Error());
                if(!belongs) throw new InvalidOperationException("대상 컨테이너 소속이 아니므로 종료하지 않았습니다.");
                if(!TerminateProcess(process,1)) throw new Win32Exception(Marshal.GetLastWin32Error());
                uint waited=WaitForSingleObject(process,3000);
                if(waited==0) return "종료 확인";
                if(waited==258) return "종료 요청 전달 · 완료 대기 중";
                throw new Win32Exception(Marshal.GetLastWin32Error(),"종료 완료 확인 실패");
            }
        }
    }
}
