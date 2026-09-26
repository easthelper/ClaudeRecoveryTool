using System;
using System.IO;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("Claude Recovery Tool")]
[assembly: AssemblyDescription("Local Windows diagnostic and selective cleanup utility for stale Claude AppX containers")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: TargetFramework(".NETFramework,Version=v4.8")]

namespace ClaudeRecovery {
    internal static class Program {
        [STAThread] static int Main(string[] args) {
            var service=new RecoveryService(new WindowsSystem(),true);
            // Read-only automation entry point. Deliberately no kill/cleanup CLI switches.
            if(args.Length==2 && args[0]=="--scan-json") {
                try { var snapshot=service.Scan(); File.WriteAllText(Path.GetFullPath(args[1]),RecoveryService.Export(snapshot),new UTF8Encoding(false)); return snapshot.Incomplete?2:0; }
                catch(Exception ex) { try { File.WriteAllText(Path.GetFullPath(args[1]),new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(new {error=ex.Message}),Encoding.UTF8); } catch { } return 3; }
            }
            if(args.Length>0) { MessageBox.Show("지원하는 인수: --scan-json <저장 경로>\r\n프로세스 종료는 화면에서만 실행할 수 있습니다.","Claude 실행 복구 도구"); return 1; }
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            Application.ThreadException+=delegate(object sender,System.Threading.ThreadExceptionEventArgs e) { MessageBox.Show(e.Exception.Message,"도구 오류",MessageBoxButtons.OK,MessageBoxIcon.Error); };
            Application.Run(new MainForm(service,true)); return 0;
        }
    }
}
