using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ClaudeRecovery {
    internal sealed class MainForm : Form {
        readonly RecoveryService service;
        readonly bool autoScan;
        readonly Label summary=new Label(), packageLabel=new Label(), footer=new Label();
        readonly Button refresh=new Button(), selectedStop=new Button(), bulkStop=new Button(), export=new Button(), launch=new Button();
        readonly CheckBox showProtected=new CheckBox();
        readonly DataGridView grid=new DataGridView();
        readonly TextBox details=new TextBox();
        Snapshot snapshot;
        bool busy, stopping, binding;
        static readonly Color Ink=Color.FromArgb(28,41,54), Muted=Color.FromArgb(89,106,120), Accent=Color.FromArgb(20,101,107);

        public MainForm(RecoveryService service, bool autoScan) {
            this.service=service; this.autoScan=autoScan;
            Text="Claude 실행 복구 도구"; ClientSize=new Size(1210,760); MinimumSize=new Size(1000,640);
            StartPosition=FormStartPosition.CenterScreen; AutoScaleMode=AutoScaleMode.Dpi;
            Font=new Font("Malgun Gothic",9F); BackColor=Color.FromArgb(244,247,249); ForeColor=Ink;
            var layout=new TableLayoutPanel { Dock=DockStyle.Fill, Padding=new Padding(20,16,20,12), ColumnCount=1, RowCount=7 };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute,40));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute,62));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute,46));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute,32));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute,130));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute,28));
            Controls.Add(layout);
            layout.Controls.Add(new Label { Text="Claude 실행 복구", Dock=DockStyle.Fill, Font=new Font(Font.FontFamily,18,FontStyle.Bold), ForeColor=Ink },0,0);
            var info=new TableLayoutPanel { Dock=DockStyle.Fill, ColumnCount=1,RowCount=2,Margin=Padding.Empty };
            info.RowStyles.Add(new RowStyle(SizeType.Absolute,31)); info.RowStyles.Add(new RowStyle(SizeType.Absolute,28));
            summary.Text="설치 버전과 남아 있는 실행 환경을 검사합니다."; summary.Dock=DockStyle.Fill; summary.Font=new Font(Font.FontFamily,11,FontStyle.Bold);
            packageLabel.Dock=DockStyle.Fill; packageLabel.ForeColor=Muted;
            info.Controls.Add(summary,0,0); info.Controls.Add(packageLabel,0,1); layout.Controls.Add(info,0,1);
            var actions=new FlowLayoutPanel { Dock=DockStyle.Fill,WrapContents=false,Margin=Padding.Empty };
            SetupButton(refresh,"다시 검사",100,Accent,Color.White);
            SetupButton(selectedStop,"선택 항목 종료",145,Color.White,Ink);
            SetupButton(bulkStop,"구버전 일괄 종료",155,Color.FromArgb(255,242,230),Color.FromArgb(135,63,22));
            SetupButton(export,"진단 저장",105,Color.White,Ink);
            SetupButton(launch,"Claude 실행",115,Color.White,Ink);
            actions.Controls.AddRange(new Control[] {refresh,selectedStop,bulkStop,export,launch}); layout.Controls.Add(actions,0,2);
            var options=new FlowLayoutPanel { Dock=DockStyle.Fill,WrapContents=false,Margin=Padding.Empty };
            showProtected.Text="현재 버전·서비스 등 보호 항목 표시"; showProtected.AutoSize=true; showProtected.Checked=false; showProtected.Margin=new Padding(2,5,25,0);
            var all=new LinkLabel { Text="후보 전체 체크",AutoSize=true,Margin=new Padding(0,5,16,0),LinkColor=Accent };
            var none=new LinkLabel { Text="체크 해제",AutoSize=true,Margin=new Padding(0,5,0,0),LinkColor=Accent };
            options.Controls.AddRange(new Control[] {showProtected,all,none}); layout.Controls.Add(options,0,3);
            ConfigureGrid(); layout.Controls.Add(grid,0,4);
            details.Multiline=true; details.ReadOnly=true; details.ScrollBars=ScrollBars.Vertical; details.Dock=DockStyle.Fill;
            details.BorderStyle=BorderStyle.FixedSingle; details.BackColor=Color.White; details.Margin=new Padding(0,10,0,0);
            details.Text="항목을 클릭하면 전체 실행 경로와 명령줄을 볼 수 있습니다.\r\n현재 버전, Windows 서비스, 다른 사용자·로그인 세션의 프로세스는 종료 대상에서 제외됩니다.";
            layout.Controls.Add(details,0,5);
            footer.Dock=DockStyle.Fill; footer.ForeColor=Muted; footer.TextAlign=ContentAlignment.MiddleLeft; layout.Controls.Add(footer,0,6);

            refresh.Click+=async delegate { await ScanAsync(); };
            selectedStop.Click+=async delegate { await StopAsync(false); };
            bulkStop.Click+=async delegate { await StopAsync(true); };
            export.Click+=delegate { SaveDiagnostic(); };
            launch.Click+=delegate { LaunchClaude(); };
            showProtected.CheckedChanged+=delegate { if(!busy) BindSnapshot(); };
            all.LinkClicked+=delegate { CheckCandidates(true); };
            none.LinkClicked+=delegate { CheckCandidates(false); };
            Shown+=async delegate { if(this.autoScan) await ScanAsync(); };
            FormClosing+=delegate(object sender,FormClosingEventArgs e) { if(stopping) { e.Cancel=true; footer.Text="종료 처리가 끝나면 도구를 닫을 수 있습니다."; } };
            SetBusy(false);
        }

        void SetupButton(Button button,string text,int width,Color back,Color fore) {
            button.Text=text; button.Size=new Size(width,35); button.Margin=new Padding(0,0,9,0); button.FlatStyle=FlatStyle.Flat;
            button.FlatAppearance.BorderColor=Color.FromArgb(199,210,217); button.BackColor=back; button.ForeColor=fore;
        }
        void ConfigureGrid() {
            grid.Dock=DockStyle.Fill; grid.Margin=Padding.Empty; grid.BackgroundColor=Color.White; grid.BorderStyle=BorderStyle.FixedSingle;
            grid.AllowUserToAddRows=false; grid.AllowUserToDeleteRows=false; grid.AllowUserToResizeRows=false;
            grid.RowHeadersVisible=false; grid.SelectionMode=DataGridViewSelectionMode.FullRowSelect; grid.MultiSelect=false;
            grid.AutoGenerateColumns=false; grid.AutoSizeRowsMode=DataGridViewAutoSizeRowsMode.None; grid.RowTemplate.Height=31;
            grid.EnableHeadersVisualStyles=false; grid.ColumnHeadersDefaultCellStyle.BackColor=Color.FromArgb(227,235,240);
            grid.ColumnHeadersDefaultCellStyle.ForeColor=Ink; grid.ColumnHeadersDefaultCellStyle.Font=new Font(Font,FontStyle.Bold);
            grid.ColumnHeadersHeight=34; grid.ColumnHeadersHeightSizeMode=DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
            grid.DefaultCellStyle.SelectionBackColor=Color.FromArgb(221,239,240); grid.DefaultCellStyle.SelectionForeColor=Ink;
            grid.AlternatingRowsDefaultCellStyle.BackColor=Color.FromArgb(249,251,252);
            grid.Columns.Add(new DataGridViewCheckBoxColumn {Name="check",HeaderText="선택",Width=47,SortMode=DataGridViewColumnSortMode.NotSortable});
            AddColumn("state","상태",180); AddColumn("task","프로그램 / 작업",175); AddColumn("pid","PID",67);
            AddColumn("name","실행 파일",118); AddColumn("version","소속 버전",105); AddColumn("started","시작 시각",156);
            grid.Columns.Add(new DataGridViewTextBoxColumn {Name="command",HeaderText="명령줄 / 경로",ReadOnly=true,AutoSizeMode=DataGridViewAutoSizeColumnMode.Fill,MinimumWidth=120,SortMode=DataGridViewColumnSortMode.NotSortable});
            grid.CurrentCellDirtyStateChanged+=delegate { if(grid.IsCurrentCellDirty) grid.CommitEdit(DataGridViewDataErrorContexts.Commit); };
            grid.CellValueChanged+=delegate { if(!binding) UpdateActions(); };
            grid.CellBeginEdit+=delegate(object sender,DataGridViewCellCancelEventArgs e) { var row=grid.Rows[e.RowIndex].Tag as ProcessRow; if(busy || row==null || !row.Eligible) e.Cancel=true; };
            grid.SelectionChanged+=delegate { if(!binding) ShowDetails(); };
            grid.DataError+=delegate(object sender,DataGridViewDataErrorEventArgs e) { e.ThrowException=false; };
        }
        void AddColumn(string name,string title,int width) { grid.Columns.Add(new DataGridViewTextBoxColumn {Name=name,HeaderText=title,Width=width,ReadOnly=true,SortMode=DataGridViewColumnSortMode.NotSortable}); }

        async Task ScanAsync() {
            if(busy) return;
            SetBusy(true); summary.Text="검사 중…"; summary.ForeColor=Ink;
            footer.Text="현재 설치 버전과 컨테이너 소속을 조회하고 있습니다.";
            try { var fresh=await Task.Run(()=>service.Scan()); if(IsDisposed) return; snapshot=fresh; BindSnapshot(); }
            catch(Exception ex) { if(!IsDisposed) { snapshot=null; grid.Rows.Clear(); summary.Text="검사를 완료하지 못했습니다."; summary.ForeColor=Color.Firebrick; details.Text=ex.Message; } }
            finally { if(!IsDisposed) SetBusy(false); }
        }

        internal void DisplaySnapshot(Snapshot value) { snapshot=value; BindSnapshot(); SetBusy(false); }
        void BindSnapshot() {
            if(snapshot==null) return;
            binding=true;
            try {
                grid.Rows.Clear();
                foreach(var row in snapshot.Processes.Where(p=>p.Eligible || showProtected.Checked || p.Reason.Contains("조회") || p.Reason.Contains("변경"))) AddRow(row);
                foreach(var job in snapshot.Containers.Where(j=>!String.IsNullOrEmpty(j.Error) || ((j.IsOld || showProtected.Checked) && j.ProcessIds.Count==0))) {
                    AddRow(new ProcessRow {JobName=job.Name,Version=job.Version,Name="(컨테이너)",Description=job.IsService?"Claude 서비스":"실행 컨테이너",Reason=job.Error!=null?"조회 불가 · 보호":job.IsOld?"구버전 잔존 · 소속 0개":job.Reason,CommandLine=job.Error??job.Name});
                }
                int count=snapshot.Candidates.Count;
                bool oldRemains=snapshot.Containers.Any(j=>j.IsOld);
                summary.Text=snapshot.Incomplete ? "검사 일부 실패 · 아래 상세 내용을 확인하세요" : count>0 ? "구버전 프로세스 "+count+"개 · 실행을 방해할 수 있습니다" : oldRemains ? "구버전 실행 환경이 남아 있지만 정리 가능한 프로세스는 없습니다" : "정리할 구버전 프로세스가 없습니다";
                summary.ForeColor=snapshot.Incomplete?Color.Firebrick:(count>0 || oldRemains)?Color.FromArgb(151,76,29):Accent;
                packageLabel.Text="설치된 Claude: "+(snapshot.Installed==null?"확인 불가":snapshot.Installed.Version)+"   |   현재 로그인 세션만 정리   |   보호 프로세스 "+snapshot.Processes.Count(p=>!p.Eligible)+"개";
                footer.Text="마지막 검사 "+DateTimeOffset.Parse(snapshot.At).LocalDateTime.ToString("HH:mm:ss")+"  ·  종료 전 설치 버전·프로세스 소속·시작 시각을 다시 확인합니다.";
                if(snapshot.Incomplete) details.Text=String.Join("\r\n",snapshot.Errors.Concat(snapshot.Containers.Where(j=>j.Error!=null).Select(j=>j.Version+": "+j.Error)));
                else if(grid.Rows.Count==0) details.Text="현재 검사에서 정리할 구버전 프로세스가 발견되지 않았습니다.\r\n이 도구는 업데이트 후 남은 구버전 실행 환경을 정리합니다. 다른 종류의 Claude 오류까지 판정하는 도구는 아닙니다.\r\n보호 항목 표시를 켜면 현재 버전과 서비스를 확인할 수 있습니다.";
                else ShowDetails();
            } finally { binding=false; }
            UpdateActions();
        }
        void AddRow(ProcessRow row) {
            string command=(row.CommandLine??row.ImagePath??"").Replace("\r"," ").Replace("\n"," ");
            int index=grid.Rows.Add(false,row.Reason,row.Description,row.Pid>0?row.Pid.ToString():"—",row.Name,row.Version??"—",row.Started,command);
            var item=grid.Rows[index]; item.Tag=row; item.Cells[0].ReadOnly=!row.Eligible; item.Cells[0].Style.BackColor=row.Eligible?Color.White:Color.FromArgb(237,241,244);
            item.Cells[1].Style.ForeColor=row.Eligible?Color.FromArgb(151,76,29):Muted;
        }
        void ShowDetails() {
            if(grid.CurrentRow==null) return;
            var row=grid.CurrentRow.Tag as ProcessRow; if(row==null) return;
            details.Text=row.Description+"  |  "+row.Reason+"\r\nPID: "+row.Pid+"   부모 PID: "+row.ParentPid+"   시작: "+row.Started+"\r\n실행 파일: "+(row.ImagePath??"조회 불가")+"\r\n명령줄: "+(row.CommandLine??"조회 불가")+"\r\n컨테이너: "+row.JobName;
        }
        List<ProcessRow> CheckedRows() { return grid.Rows.Cast<DataGridViewRow>().Where(r=>Convert.ToBoolean(r.Cells[0].Value)).Select(r=>r.Tag as ProcessRow).Where(p=>p!=null && p.Eligible).ToList(); }
        void CheckCandidates(bool value) { if(busy) return; binding=true; foreach(DataGridViewRow item in grid.Rows) if(((ProcessRow)item.Tag).Eligible) item.Cells[0].Value=value; binding=false; UpdateActions(); }
        void UpdateActions() {
            int count=CheckedRows().Count;
            selectedStop.Text="선택 항목 종료"+(count>0?" ("+count+")":"");
            selectedStop.Enabled=!busy && count>0; bulkStop.Enabled=!busy && snapshot!=null && snapshot.Candidates.Count>0;
            bulkStop.BackColor=bulkStop.Enabled?Color.FromArgb(255,242,230):Color.FromArgb(235,239,242);
            bulkStop.ForeColor=bulkStop.Enabled?Color.FromArgb(135,63,22):Muted;
            selectedStop.BackColor=selectedStop.Enabled?Color.White:Color.FromArgb(235,239,242);
            export.Enabled=!busy && snapshot!=null;
        }
        void SetBusy(bool value) { busy=value; refresh.Enabled=!value; showProtected.Enabled=!value; launch.Enabled=!value; grid.Enabled=!value; UseWaitCursor=value; UpdateActions(); }

        async Task StopAsync(bool all) {
            if(busy || snapshot==null) return;
            var targets=all?snapshot.Candidates:CheckedRows(); if(targets.Count==0) return;
            using(var confirm=new ConfirmStopForm(targets)) if(confirm.ShowDialog(this)!=DialogResult.OK) return;
            SetBusy(true); stopping=true; bool refreshAfterFailure=false; footer.Text="승인한 대상의 소속과 시작 시각을 확인하며 종료 중입니다…";
            try {
                var shown=snapshot;
                string logDir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ClaudeRecoveryTool","Logs");
                StopReport report=await Task.Run(()=>service.Stop(shown,targets,logDir));
                snapshot=await Task.Run(()=>service.Scan()); BindSnapshot();
                details.Text=String.Join("\r\n",report.Outcomes.Select(r=>"PID "+r.Pid+" "+r.Name+": "+r.Result))+"\r\n\r\n남은 정리 후보: "+snapshot.Candidates.Count+"개\r\n기록: "+report.AuditPath;
                footer.Text="종료 처리 후 재검사 완료 · 남아 있거나 새로 생성된 프로세스는 추가 승인 없이 종료하지 않습니다.";
            } catch(Exception ex) {
                MessageBox.Show(this,ex.Message,"종료 처리 결과",MessageBoxButtons.OK,MessageBoxIcon.Warning);
                refreshAfterFailure=true;
            } finally { stopping=false; SetBusy(false); }
            if(refreshAfterFailure) await ScanAsync();
        }

        void SaveDiagnostic() {
            if(snapshot==null) return;
            using(var dialog=new SaveFileDialog {Filter="진단 JSON (*.json)|*.json",FileName="claude-diagnostic-"+DateTime.Now.ToString("yyyyMMdd-HHmmss")+".json"}) {
                if(dialog.ShowDialog(this)!=DialogResult.OK) return;
                try { File.WriteAllText(dialog.FileName,RecoveryService.Export(snapshot),new System.Text.UTF8Encoding(false)); footer.Text="진단 저장 완료 · 명령줄 원문은 저장하지 않았습니다."; }
                catch(Exception ex) { MessageBox.Show(this,ex.Message,"저장 실패",MessageBoxButtons.OK,MessageBoxIcon.Error); }
            }
        }
        void LaunchClaude() {
            object shell=null;
            try {
                Type type=Type.GetTypeFromProgID("Shell.Application"); shell=Activator.CreateInstance(type);
                type.InvokeMember("ShellExecute",BindingFlags.InvokeMethod,null,shell,new object[] {"explorer.exe",@"shell:AppsFolder\"+Policy.Family+"!Claude","","open",1});
                footer.Text="Windows 탐색기에 Claude 실행을 요청했습니다. 실제 창이 열리는지 확인하세요.";
            } catch(Exception ex) { MessageBox.Show(this,ex.Message,"Claude 실행 요청 실패",MessageBoxButtons.OK,MessageBoxIcon.Warning); }
            finally { if(shell!=null) Marshal.FinalReleaseComObject(shell); }
        }

        internal int TestVisibleCount { get { return grid.Rows.Count; } }
        internal bool TestBulkEnabled { get { return bulkStop.Enabled; } }
        internal bool TestSelectedEnabled { get { return selectedStop.Enabled; } }
        internal void TestCheckAll() { CheckCandidates(true); }
        internal void TestShowProtected() { showProtected.Checked=true; }
        internal string TestSummary { get { return summary.Text; } }
    }

    internal sealed class ConfirmStopForm : Form {
        public ConfirmStopForm(IList<ProcessRow> targets) {
            Text="종료할 프로세스 확인"; ClientSize=new Size(730,465); MinimumSize=new Size(620,400); StartPosition=FormStartPosition.CenterParent;
            Font=new Font("Malgun Gothic",9F); BackColor=Color.White; MinimizeBox=false; MaximizeBox=false;
            var layout=new TableLayoutPanel {Dock=DockStyle.Fill,Padding=new Padding(18),ColumnCount=1,RowCount=4};
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute,36)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute,75));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent,100)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute,46)); Controls.Add(layout);
            layout.Controls.Add(new Label {Text=targets.Count+"개 프로세스를 종료합니다",Font=new Font(Font,FontStyle.Bold),Dock=DockStyle.Fill},0,0);
            layout.Controls.Add(new Label {Text="진행 중인 원격 요청·개발 서버·로그 창이 중단될 수 있습니다.\r\n콘솔을 종료하면 연결된 프로세스도 함께 종료될 수 있습니다.\r\n종료한 프로그램은 자동으로 다시 시작하지 않습니다.",Dock=DockStyle.Fill},0,1);
            var list=new ListBox {Dock=DockStyle.Fill,HorizontalScrollbar=true};
            foreach(var row in targets) list.Items.Add("PID "+row.Pid+"  "+row.Name+"  |  "+row.Description+"  |  "+row.Version);
            layout.Controls.Add(list,0,2);
            var buttons=new FlowLayoutPanel {Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft,Padding=new Padding(0,9,0,0)};
            var cancel=new Button {Text="취소",DialogResult=DialogResult.Cancel,Size=new Size(100,30)};
            var proceed=new Button {Text="위 항목 종료",DialogResult=DialogResult.OK,Size=new Size(140,30),BackColor=Color.FromArgb(255,235,222)};
            buttons.Controls.Add(cancel); buttons.Controls.Add(proceed); layout.Controls.Add(buttons,0,3); CancelButton=cancel; AcceptButton=cancel;
        }
    }
}
