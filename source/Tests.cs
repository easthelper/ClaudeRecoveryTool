using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace ClaudeRecovery {
    internal sealed class FakeSystem : IRecoverySystem {
        public PackageInfo Package=new PackageInfo { FullName="Claude_2.99.0.0_x64__pzs8sxrjxfjjc",FamilyName=Policy.Family,Version="2.99.0.0",Status="Ok" };
        public string UserSid { get { return "S-1-5-21-111-222-333-1001"; } }
        public int SessionId { get { return 7; } }
        public Dictionary<string,List<int>> Jobs=new Dictionary<string,List<int>>();
        public Dictionary<int,ProcessIdentity> Processes=new Dictionary<int,ProcessIdentity>();
        public List<int> Stopped=new List<int>();
        public bool DenyMembers;
        public int PackageCalls, ChangeAtCall;
        public PackageInfo InstalledPackage() {
            PackageCalls++;
            if(ChangeAtCall>0 && PackageCalls>=ChangeAtCall) return new PackageInfo {FullName="Claude_2.98.0.0_x64__pzs8sxrjxfjjc",FamilyName=Policy.Family,Version="2.98.0.0",Status="Ok"};
            return Package;
        }
        public List<string> JobNames() { return Jobs.Keys.ToList(); }
        public List<int> Members(string name) { if(DenyMembers) throw new UnauthorizedAccessException("test: denied"); return Jobs[name].ToList(); }
        public ProcessIdentity Identity(int pid) { return Processes[pid]; }
        public string Terminate(string name,ProcessIdentity expected,int session) {
            var live=Processes[expected.Pid];
            if(live.CreatedFileTime!=expected.CreatedFileTime) throw new InvalidOperationException("test: PID reused");
            Stopped.Add(expected.Pid); Jobs[name].Remove(expected.Pid); return "종료 확인";
        }
        public string Name(string version,string owner) { return "\\Container_Claude_"+version+"_x64__pzs8sxrjxfjjc-"+owner; }
        public void Add(int pid,string version,string filename) {
            string name=Name(version,UserSid);
            if(!Jobs.ContainsKey(name)) Jobs[name]=new List<int>();
            Jobs[name].Add(pid);
            Processes[pid]=new ProcessIdentity {Pid=pid,CreatedFileTime=DateTime.UtcNow.AddHours(-5).ToFileTimeUtc()+pid,ImagePath="C:\\Example\\"+filename,SessionId=SessionId};
        }
    }

    internal static class Tests {
        static int passed;
        static string outputDirectory;
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr security,string name);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(KernelHandle job,IntPtr process);
        static void Check(bool value,string name) { if(!value) throw new Exception("FAIL: "+name); passed++; Console.WriteLine("PASS: "+name); }
        static void Reject(Action action,string name) { bool rejected=false; try { action(); } catch { rejected=true; } Check(rejected,name); }
        static FakeSystem Two() { var fake=new FakeSystem(); fake.Add(20001,"2.1.0.0","node.exe"); fake.Add(20002,"2.1.0.0","pythonw.exe"); return fake; }

        [STAThread] public static int Main(string[] args) {
            if(args.Length>0 && args[0]=="--test-child") { Thread.Sleep(120000); return 0; }
            outputDirectory=args.Length>0?Path.GetFullPath(args[0]):Path.Combine(Path.GetTempPath(),"ClaudeRecoveryTests");
            Directory.CreateDirectory(outputDirectory);
            try {
                PolicyTests(); ServiceTests(); NativeTests(); UiTests();
                Console.WriteLine("RESULT: "+passed+" checks passed"); return 0;
            } catch(Exception ex) { Console.Error.WriteLine(ex); return 1; }
        }

        static void PolicyTests() {
            var fake=Two(); var package=fake.Package; string sid=fake.UserSid;
            Check(Policy.Classify(fake.Name("2.1.0.0",sid),package,sid).Eligible,"older own-user container eligible");
            Check(!Policy.Classify(fake.Name("2.99.0.0",sid),package,sid).Eligible,"current version protected");
            Check(!Policy.Classify(fake.Name("3.0.0.0",sid),package,sid).Eligible,"newer/rollback version protected");
            Check(!Policy.Classify(fake.Name("2.1.0.0","PackagedService"),package,sid).Eligible,"packaged service protected");
            Check(!Policy.Classify(fake.Name("2.1.0.0",sid+"-1"),package,sid).Eligible,"different user protected");
            Check(!Policy.Classify(fake.Name("2.1.0.0",sid),null,sid).Eligible,"unknown installed package protected");
            Check(!Policy.Classify("\\Container_Claude_fake",package,sid).Eligible,"malformed container name protected");
            Check(!Policy.Classify(fake.Name("2.1.0.0",sid).Replace("pzs8sxrjxfjjc","anotherpublisher"),package,sid).Eligible,"other publisher protected");
            var job=Policy.Classify(fake.Name("2.1.0.0",sid),package,sid);
            var identity=fake.Identity(20001); identity.SessionId=8;
            Check(Policy.Eligibility(job,identity,7)!=null,"other login session protected");
            identity.SessionId=7; identity.Critical=true;
            Check(Policy.Eligibility(job,identity,7)!=null,"critical process protected");
            Check(Policy.Describe("node.exe","node vite/bin/vite.js")=="Vite 개발 서버","development server description");
        }

        static void ServiceTests() {
            var fake=Two(); var service=new RecoveryService(fake,false); var shown=service.Scan();
            Check(shown.Candidates.Count==2,"scan finds both stale members");
            fake.Add(20003,"2.1.0.0","newly-spawned.exe");
            var report=service.Stop(shown,new [] {shown.Processes[0]},outputDirectory);
            Check(fake.Stopped.SequenceEqual(new [] {20001}),"selection stops only the approved process");
            Check(fake.Jobs.Values.Single().Contains(20002) && fake.Jobs.Values.Single().Contains(20003),"unselected and new processes preserved");
            Check(report.Outcomes.Count==1 && File.Exists(report.AuditPath),"cleanup audit persisted");
            Reject(()=>service.Stop(shown,new [] {new ProcessRow {Pid=20002,Eligible=true,JobName=shown.Processes[1].JobName}},outputDirectory),"forged/unshown row rejected");
            fake=Two(); service=new RecoveryService(fake,false); shown=service.Scan(); fake.Package.FullName="changed";
            // Snapshot must be immutable relative to runtime provider mutations.
            shown.Installed=new PackageInfo {FullName="Claude_2.99.0.0_x64__pzs8sxrjxfjjc",FamilyName=Policy.Family,Version="2.99.0.0",Status="Ok"};
            Reject(()=>service.Stop(shown,shown.Candidates,outputDirectory),"package drift before stop aborts");
            Check(fake.Stopped.Count==0,"package drift does not terminate any process");
            fake=Two(); service=new RecoveryService(fake,false); shown=service.Scan(); fake.ChangeAtCall=4;
            report=service.Stop(shown,shown.Candidates,outputDirectory);
            Check(fake.Stopped.Count==1 && report.Outcomes.Last().Failed,"package drift during batch stops further cleanup");
            fake=Two(); fake.DenyMembers=true; shown=new RecoveryService(fake,false).Scan();
            Check(shown.Incomplete && shown.Candidates.Count==0,"access denied is incomplete, never healthy");
            fake=Two(); service=new RecoveryService(fake,false); shown=service.Scan();
            fake.Processes[20001].CreatedFileTime++;
            report=service.Stop(shown,new [] {shown.Processes[0]},outputDirectory);
            Check(report.Outcomes[0].Failed && fake.Stopped.Count==0,"reused PID rejected at stop");
            shown.Processes[0].CommandLine="node --token SUPER_PRIVATE_TEST_TOKEN";
            Check(!RecoveryService.Export(shown).Contains("SUPER_PRIVATE_TEST_TOKEN"),"saved diagnostic excludes raw command line");
            fake=Two(); fake.Add(20004,"2.99.0.0","Claude.exe"); service=new RecoveryService(fake,false); shown=service.Scan();
            var current=shown.Processes.Single(p=>p.Pid==20004); current.Eligible=true;
            Reject(()=>service.Stop(shown,new [] {current},outputDirectory),"current-version cleanup rejected even if UI eligibility is tampered");
            Check(fake.Stopped.Count==0,"current-version guard leaves all processes untouched");
            fake=Two(); fake.Add(20004,"2.99.0.0","Claude.exe"); service=new RecoveryService(fake,false); shown=service.Scan();
            report=service.Stop(shown,shown.Candidates,outputDirectory);
            Check(fake.Stopped.OrderBy(p=>p).SequenceEqual(new [] {20001,20002}) && report.Outcomes.All(o=>!o.Failed),"bulk cleanup terminates every approved stale member");
            Check(fake.Jobs[fake.Name("2.99.0.0",fake.UserSid)].Contains(20004),"bulk cleanup preserves current-version member");
        }

        static Process Child() {
            return Process.Start(new ProcessStartInfo {FileName=System.Reflection.Assembly.GetExecutingAssembly().Location,Arguments="--test-child",UseShellExecute=false,CreateNoWindow=true});
        }
        static ProcessIdentity ReadIdentity(Process child) { using(var handle=Native.OpenProcessForInspection(child.Id,false)) return Native.Identity(handle,child.Id); }
        static void NativeTests() {
            using(var job=new KernelHandle(CreateJobObject(IntPtr.Zero,"ClaudeRecoverySelfTest-"+Guid.NewGuid().ToString("N"))))
            using(var first=Child()) using(var second=Child()) using(var outsider=Child()) {
                try {
                    Check(!job.IsInvalid && AssignProcessToJobObject(job,first.Handle) && AssignProcessToJobObject(job,second.Handle),"isolated real Win32 job created with two harmless test children");
                    var one=ReadIdentity(first); var two=ReadIdentity(second); var outside=ReadIdentity(outsider);
                    Check(Native.Members(job).Contains(first.Id) && Native.Members(job).Contains(second.Id),"native job membership enumerated");
                    var wrong=new ProcessIdentity {Pid=one.Pid,CreatedFileTime=one.CreatedFileTime+1,ImagePath=one.ImagePath,SessionId=one.SessionId};
                    Reject(()=>Native.TerminateVerified(job,wrong,one.SessionId),"native creation-time mismatch blocked");
                    Check(!first.HasExited,"creation-time rejection leaves process alive");
                    Reject(()=>Native.TerminateVerified(job,outside,outside.SessionId),"native nonmember termination blocked");
                    Check(!outsider.HasExited,"unrelated test process remains alive");
                    Reject(()=>Native.TerminateVerified(job,one,one.SessionId+1),"native other-session guard blocked");
                    Check(Native.TerminateVerified(job,one,one.SessionId)=="종료 확인" && first.WaitForExit(3000),"native selected member terminated and waited");
                    Check(!second.HasExited && !outsider.HasExited,"native unselected and unrelated processes preserved");
                    Check(Native.TerminateVerified(job,two,two.SessionId)=="종료 확인" && second.WaitForExit(3000),"native remaining member terminated");
                    Check(Native.Members(job).Count==0,"native job empty after cleanup");
                } finally {
                    foreach(var child in new [] {first,second,outsider}) try { if(!child.HasExited) { child.Kill(); child.WaitForExit(3000); } } catch { }
                }
            }
            Check(Native.EnumerateClaudeJobs().All(n=>n.StartsWith("\\Container_Claude_",StringComparison.Ordinal)),"live read-only enumeration is scoped to Claude jobs");
        }

        static void UiTests() {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            var fake=Two(); fake.Add(20004,"2.99.0.0","Claude.exe");
            var snapshot=new RecoveryService(fake,false).Scan();
            snapshot.Processes[0].Description="launcher 개발 서버"; snapshot.Processes[0].CommandLine="node D:\\Example\\launcher\\node_modules\\vite\\bin\\vite.js";
            snapshot.Processes[1].Description="RC Manager"; snapshot.Processes[1].CommandLine="pythonw C:\\Example\\rcm.pyw";
            using(var form=new MainForm(new RecoveryService(fake,false),false)) {
                form.DisplaySnapshot(snapshot);
                Check(form.TestVisibleCount==2 && form.TestBulkEnabled,"UI shows stale candidates and enables batch cleanup");
                Check(!form.TestSelectedEnabled,"UI requires checkbox selection for selective cleanup");
                form.TestCheckAll(); Check(form.TestSelectedEnabled,"UI select-all checks only eligible rows");
                form.TestShowProtected(); Check(form.TestVisibleCount==3,"UI can show protected current version");
                form.TestCheckAll();
                form.StartPosition=FormStartPosition.Manual; form.Location=new Point(-20000,-20000); form.ShowInTaskbar=false; form.Show(); Application.DoEvents();
                using(var bitmap=new Bitmap(form.Width,form.Height)) { form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,form.Size)); bitmap.Save(Path.Combine(outputDirectory,"ui-candidates.png"),System.Drawing.Imaging.ImageFormat.Png); }
                fake.DenyMembers=true; form.DisplaySnapshot(new RecoveryService(fake,false).Scan());
                Check(form.TestSummary.Contains("실패") && !form.TestBulkEnabled,"UI access-denied state cannot claim healthy or clean");
                fake.DenyMembers=false; fake.Jobs.Clear(); form.DisplaySnapshot(new RecoveryService(fake,false).Scan());
                Check(!form.TestBulkEnabled && form.TestSummary.Contains("없습니다"),"UI healthy state disables cleanup");
                using(var bitmap=new Bitmap(form.Width,form.Height)) { form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,form.Size)); bitmap.Save(Path.Combine(outputDirectory,"ui-healthy.png"),System.Drawing.Imaging.ImageFormat.Png); }
                fake.Jobs[fake.Name("2.1.0.0",fake.UserSid)]=new List<int>(); form.DisplaySnapshot(new RecoveryService(fake,false).Scan());
                Check(form.TestSummary.Contains("남아") && form.TestVisibleCount>0 && !form.TestBulkEnabled,"empty stale container is visible as unresolved, not healthy");
                form.Close();
            }
        }
    }
}
