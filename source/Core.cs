using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace ClaudeRecovery {
    internal sealed class PackageInfo {
        public string FullName, FamilyName, Version, Status;
    }
    internal sealed class ContainerInfo {
        public string Name, PackageName, Version, OwnerSid, Reason, Error;
        public bool IsService, IsOld, Eligible;
        public List<int> ProcessIds=new List<int>();
    }
    internal sealed class ProcessRow {
        public string JobName, Version, Name, ImagePath, CommandLine, Description, Reason;
        public int Pid, ParentPid, SessionId;
        public long CreatedFileTime;
        public bool Eligible;
        public ProcessIdentity Identity() { return new ProcessIdentity { Pid=Pid, CreatedFileTime=CreatedFileTime, ImagePath=ImagePath, SessionId=SessionId }; }
        public string Started { get { return CreatedFileTime>0 ? DateTime.FromFileTimeUtc(CreatedFileTime).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : "조회 불가"; } }
    }
    internal sealed class Snapshot {
        public string At=DateTimeOffset.Now.ToString("o");
        public PackageInfo Installed;
        public string UserSid;
        public int SessionId;
        public List<ContainerInfo> Containers=new List<ContainerInfo>();
        public List<ProcessRow> Processes=new List<ProcessRow>();
        public List<string> Errors=new List<string>();
        public List<ProcessRow> Candidates { get { return Processes.Where(p=>p.Eligible).ToList(); } }
        public bool Incomplete { get { return Errors.Count>0 || Containers.Any(j=>!String.IsNullOrEmpty(j.Error)); } }
        // Only failures that undermine container/process membership validation block cleanup.
        // WMI enrichment failures still mark the scan incomplete, but do not weaken termination checks.
        public bool CleanupBlocked { get { return Installed==null || Containers.Any(j=>!String.IsNullOrEmpty(j.Error)); } }
    }
    internal sealed class StopOutcome {
        public int Pid;
        public string Name, Result;
        public bool Failed;
    }
    internal sealed class StopReport {
        public string AuditPath;
        public List<StopOutcome> Outcomes=new List<StopOutcome>();
    }

    internal static class Policy {
        internal const string Family="Claude_pzs8sxrjxfjjc";
        static readonly Regex JobPattern=new Regex(@"^\\Container_(Claude_(\d+\.\d+\.\d+\.\d+)_(?:x64|arm64|x86|neutral)__pzs8sxrjxfjjc)-(PackagedService|S-1-\d+(?:-\d+)+)$",RegexOptions.CultureInvariant);
        public static ContainerInfo Classify(string name, PackageInfo installed, string sid) {
            var info=new ContainerInfo { Name=name, Reason="식별 불가 · 보호" };
            Match match=JobPattern.Match(name);
            if(!match.Success) return info;
            info.PackageName=match.Groups[1].Value; info.Version=match.Groups[2].Value; info.OwnerSid=match.Groups[3].Value;
            info.IsService=info.OwnerSid=="PackagedService";
            if(info.IsService) { info.Reason="서비스 · 보호"; return info; }
            if(info.OwnerSid!=sid) { info.Reason="다른 사용자 · 보호"; return info; }
            if(installed==null || installed.FamilyName!=Family || installed.Status!="Ok") { info.Reason="설치 상태 확인 불가 · 보호"; return info; }
            Version oldVersion, currentVersion;
            if(!System.Version.TryParse(info.Version,out oldVersion) || !System.Version.TryParse(installed.Version,out currentVersion)) { info.Reason="버전 확인 불가 · 보호"; return info; }
            if(info.PackageName==installed.FullName || oldVersion==currentVersion) { info.Reason="현재 버전 · 보호"; return info; }
            if(oldVersion>currentVersion) { info.Reason="설치 버전보다 새 버전 · 보호"; return info; }
            info.IsOld=true; info.Eligible=true; info.Reason="구버전 · 정리 후보";
            return info;
        }

        public static string Eligibility(ContainerInfo job, ProcessIdentity identity, int session) {
            if(!job.Eligible) return job.Reason;
            if(identity.Pid<=4 || identity.Pid==Process.GetCurrentProcess().Id || identity.Critical) return "시스템/도구 자체 · 보호";
            if(identity.SessionId!=session) return "다른 로그인 세션 · 보호";
            if(identity.CreatedFileTime<=0 || String.IsNullOrEmpty(identity.ImagePath)) return "프로세스 식별 불가 · 보호";
            return null;
        }

        public static string Describe(string name, string command) {
            command=command??"";
            if(command.IndexOf("rcm.pyw",StringComparison.OrdinalIgnoreCase)>=0) return "RC Manager";
            if(command.IndexOf("remote-control",StringComparison.OrdinalIgnoreCase)>=0) {
                var m=Regex.Match(command,@"--name\s+(?:""([^""]+)""|(\S+))");
                return "Claude 원격 연결"+(m.Success ? " · "+(m.Groups[1].Success?m.Groups[1].Value:m.Groups[2].Value) : "");
            }
            if(command.IndexOf("Get-Content",StringComparison.OrdinalIgnoreCase)>=0 && command.IndexOf("-Wait",StringComparison.OrdinalIgnoreCase)>=0) return "로그 감시 창";
            if(command.IndexOf("vite",StringComparison.OrdinalIgnoreCase)>=0) return "Vite 개발 서버";
            if(command.IndexOf("tsx",StringComparison.OrdinalIgnoreCase)>=0) return "Node/TypeScript 서버";
            if(command.IndexOf("npm",StringComparison.OrdinalIgnoreCase)>=0 && command.IndexOf("run dev",StringComparison.OrdinalIgnoreCase)>=0) return "npm 개발 서버";
            if(name.Equals("conhost.exe",StringComparison.OrdinalIgnoreCase)) return "콘솔 호스트";
            return name;
        }
    }

    internal interface IRecoverySystem {
        PackageInfo InstalledPackage();
        string UserSid { get; }
        int SessionId { get; }
        List<string> JobNames();
        List<int> Members(string name);
        ProcessIdentity Identity(int pid);
        string Terminate(string job, ProcessIdentity expected, int session);
    }

    internal sealed class WindowsSystem : IRecoverySystem {
        public string UserSid { get { return WindowsIdentity.GetCurrent().User.Value; } }
        public int SessionId { get { return Process.GetCurrentProcess().SessionId; } }
        public List<string> JobNames() { return Native.EnumerateClaudeJobs(); }
        public List<int> Members(string name) { using(var job=Native.OpenJob(name)) return Native.Members(job); }
        public ProcessIdentity Identity(int pid) { using(var process=Native.OpenProcessForInspection(pid,false)) return Native.Identity(process,pid); }
        public string Terminate(string jobName, ProcessIdentity expected, int session) { using(var job=Native.OpenJob(jobName)) return Native.TerminateVerified(job,expected,session); }

        public PackageInfo InstalledPackage() {
            const string script="[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); $ErrorActionPreference='Stop'; @(Get-AppxPackage -Name Claude | Where-Object {$_.PackageFamilyName -eq 'Claude_pzs8sxrjxfjjc'} | Select-Object PackageFullName,PackageFamilyName,@{n='Version';e={$_.Version.ToString()}},@{n='Status';e={$_.Status.ToString()}}) | ConvertTo-Json -Compress";
            var info=new ProcessStartInfo {
                FileName=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),@"System32\WindowsPowerShell\v1.0\powershell.exe"),
                Arguments="-NoLogo -NoProfile -NonInteractive -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(script)),
                UseShellExecute=false, CreateNoWindow=true, RedirectStandardOutput=true, RedirectStandardError=true,
                StandardOutputEncoding=Encoding.UTF8, StandardErrorEncoding=Encoding.UTF8
            };
            using(var process=Process.Start(info)) {
                var output=process.StandardOutput.ReadToEndAsync(); var error=process.StandardError.ReadToEndAsync();
                if(!process.WaitForExit(20000)) { try { process.Kill(); } catch { } throw new InvalidOperationException("설치 버전 조회 시간이 초과되었습니다."); }
                if(process.ExitCode!=0) throw new InvalidOperationException("설치 버전 조회 실패: "+error.Result.Trim());
                if(String.IsNullOrWhiteSpace(output.Result)) throw new InvalidOperationException("현재 Windows 계정에서 Claude 설치 정보를 찾지 못했습니다.");
                object parsed=new JavaScriptSerializer().DeserializeObject(output.Result);
                var array=parsed as object[];
                if(array!=null) { if(array.Length!=1) throw new InvalidOperationException("설치 패키지가 여러 개이거나 없습니다. 자동 정리를 차단했습니다."); parsed=array[0]; }
                var item=parsed as Dictionary<string,object>;
                if(item==null) throw new InvalidOperationException("설치 정보 형식을 확인하지 못했습니다.");
                var package=new PackageInfo { FullName=Convert.ToString(item["PackageFullName"]),FamilyName=Convert.ToString(item["PackageFamilyName"]),Version=Convert.ToString(item["Version"]),Status=Convert.ToString(item["Status"]) };
                if(package.Status!="Ok") throw new InvalidOperationException("Claude 설치 상태가 정상(Ok)이 아닙니다: "+package.Status);
                return package;
            }
        }
    }

    internal sealed class RecoveryService {
        readonly IRecoverySystem system;
        readonly bool useWmi;
        public RecoveryService(IRecoverySystem system, bool useWmi) { this.system=system; this.useWmi=useWmi; }

        public Snapshot Scan() {
            var result=new Snapshot { UserSid=system.UserSid, SessionId=system.SessionId };
            try { result.Installed=system.InstalledPackage(); } catch(Exception ex) { result.Errors.Add(ex.Message); }
            List<string> names;
            try { names=system.JobNames(); } catch(Exception ex) { result.Errors.Add(ex.Message); return result; }
            foreach(string name in names) {
                var job=Policy.Classify(name,result.Installed,result.UserSid);
                result.Containers.Add(job);
                // Other users and services are visible as protected groups, without reading their command lines.
                if(job.IsService || (job.OwnerSid!=null && job.OwnerSid!=result.UserSid)) continue;
                try { job.ProcessIds=system.Members(name); } catch(Exception ex) { job.Error=ex.Message; continue; }
                foreach(int pid in job.ProcessIds) {
                    var row=new ProcessRow { Pid=pid, JobName=name, Version=job.Version, Name="(조회 중)", Reason=job.Reason };
                    result.Processes.Add(row);
                    try {
                        var identity=system.Identity(pid);
                        row.CreatedFileTime=identity.CreatedFileTime; row.ImagePath=identity.ImagePath; row.Name=Path.GetFileName(identity.ImagePath); row.SessionId=identity.SessionId;
                        string blocked=Policy.Eligibility(job,identity,result.SessionId);
                        row.Eligible=blocked==null; row.Reason=blocked??job.Reason;
                    } catch(Exception ex) { row.Reason="프로세스 조회 불가 · 보호"; job.Error="일부 프로세스 조회 실패: "+ex.Message; }
                    row.Description=row.Name;
                }
            }
            if(useWmi && result.Processes.Count>0) FillDescriptions(result);
            result.Processes=result.Processes.OrderByDescending(p=>p.Eligible).ThenBy(p=>p.JobName).ThenBy(p=>p.CreatedFileTime).ThenBy(p=>p.Pid).ToList();
            return result;
        }

        static void FillDescriptions(Snapshot snapshot) {
            try {
                using(var searcher=new ManagementObjectSearcher("SELECT ProcessId,ParentProcessId,CreationDate,CommandLine FROM Win32_Process"))
                using(var items=searcher.Get()) {
                    var byId=snapshot.Processes.GroupBy(p=>p.Pid).ToDictionary(g=>g.Key,g=>g.ToList());
                    foreach(ManagementObject item in items) using(item) {
                        int pid=Convert.ToInt32(item["ProcessId"]);
                        List<ProcessRow> rows;
                        if(!byId.TryGetValue(pid,out rows)) continue;
                        string created=Convert.ToString(item["CreationDate"]);
                        long wmiTime=String.IsNullOrEmpty(created)?0:ManagementDateTimeConverter.ToDateTime(created).ToUniversalTime().ToFileTimeUtc();
                        foreach(var row in rows) {
                            if(row.CreatedFileTime<=0 || Math.Abs(wmiTime-row.CreatedFileTime)>10000) { row.Eligible=false; row.Reason="프로세스 정보 변경 · 다시 검사"; continue; }
                            row.ParentPid=Convert.ToInt32(item["ParentProcessId"]);
                            row.CommandLine=Convert.ToString(item["CommandLine"]);
                            row.Description=Policy.Describe(row.Name,row.CommandLine);
                        }
                    }
                }
            } catch(Exception ex) { snapshot.Errors.Add("명령줄/부모 프로세스 조회 실패: "+ex.Message); }
        }

        // No destructive CLI is exposed. The GUI passes only rows shown in its confirmed snapshot.
        public StopReport Stop(Snapshot shown, IList<ProcessRow> selected, string logDirectory) {
            if(shown==null || shown.Installed==null || selected.Count==0) throw new InvalidOperationException("종료할 대상을 다시 검사하세요.");
            if(shown.CleanupBlocked) throw new InvalidOperationException("안전 확인에 필요한 일부 조회가 실패하여 종료를 차단했습니다. 다시 검사하세요.");
            if(system.UserSid!=shown.UserSid || system.SessionId!=shown.SessionId) throw new InvalidOperationException("Windows 사용자 또는 로그인 세션이 바뀌었습니다.");
            var current=system.InstalledPackage();
            if(current.FullName!=shown.Installed.FullName || current.Status!="Ok") throw new InvalidOperationException("검사 후 Claude 설치 버전이 바뀌었습니다. 다시 검사하세요.");
            var targets=selected.GroupBy(p=>p.JobName+"|"+p.Pid).Select(g=>g.First()).ToList();
            foreach(var row in targets) {
                if(!shown.Processes.Contains(row) || !row.Eligible || !Policy.Classify(row.JobName,current,shown.UserSid).Eligible) throw new InvalidOperationException("보호된 대상이 포함되어 종료를 차단했습니다.");
            }
            Directory.CreateDirectory(logDirectory);
            var report=new StopReport { AuditPath=Path.Combine(logDirectory,"cleanup-"+DateTime.Now.ToString("yyyyMMdd-HHmmss-fff")+"-"+Guid.NewGuid().ToString("N").Substring(0,6)+".jsonl") };
            using(var audit=new StreamWriter(new FileStream(report.AuditPath,FileMode.CreateNew,FileAccess.Write,FileShare.Read),new UTF8Encoding(false))) {
                audit.AutoFlush=true;
                var json=new JavaScriptSerializer();
                audit.WriteLine(json.Serialize(new { kind="approved-targets", at=DateTimeOffset.Now.ToString("o"), package=current.FullName, targets=targets.Select(p=>new { p.Pid,p.Name,p.ImagePath,p.CreatedFileTime,p.JobName }).ToArray() }));
                foreach(var row in targets) {
                    var outcome=new StopOutcome { Pid=row.Pid, Name=row.Name };
                    try {
                        // Re-query package registration before each individual termination.
                        // An update or rollback in the middle of a batch must stop the batch.
                        var livePackage=system.InstalledPackage();
                        if(livePackage.FullName!=current.FullName || !Policy.Classify(row.JobName,livePackage,shown.UserSid).Eligible) {
                            outcome.Result="설치 상태 변경 · 이후 종료 중단"; outcome.Failed=true;
                            report.Outcomes.Add(outcome); audit.WriteLine(json.Serialize(outcome)); break;
                        }
                        if(!system.Members(row.JobName).Contains(row.Pid)) outcome.Result="이미 컨테이너에서 해제됨";
                        else outcome.Result=system.Terminate(row.JobName,row.Identity(),shown.SessionId);
                    } catch(Exception ex) { outcome.Failed=true; outcome.Result=ex.Message; }
                    report.Outcomes.Add(outcome); audit.WriteLine(json.Serialize(outcome));
                }
            }
            return report;
        }

        public static string Export(Snapshot snapshot) {
            // Command lines can contain access tokens. They are displayed locally but omitted from saved diagnostics.
            return new JavaScriptSerializer { MaxJsonLength=8*1024*1024 }.Serialize(new {
                tool="Claude Recovery Tool 1.0.0", snapshot.At,snapshot.UserSid,snapshot.SessionId,
                installed=snapshot.Installed, incomplete=snapshot.Incomplete, errors=snapshot.Errors,
                containers=snapshot.Containers,
                processes=snapshot.Processes.Select(p=>new {p.Pid,p.ParentPid,p.Name,p.Description,p.ImagePath,p.Started,p.CreatedFileTime,p.SessionId,p.Version,p.JobName,p.Eligible,p.Reason}).ToArray()
            });
        }
    }
}
