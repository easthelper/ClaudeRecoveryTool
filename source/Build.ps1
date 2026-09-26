param([string]$OutputDirectory = (Split-Path -Parent $PSScriptRoot), [switch]$Tests)
$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '.NET Framework C# compiler was not found.' }
[void](New-Item -ItemType Directory -Path $OutputDirectory -Force)
$output = [IO.Path]::GetFullPath($OutputDirectory)
$sources = @('Native.cs','Core.cs','MainForm.cs','Program.cs') | ForEach-Object { Join-Path $PSScriptRoot $_ }
$references = @('/r:System.dll','/r:System.Core.dll','/r:System.Drawing.dll','/r:System.Windows.Forms.dll','/r:System.Management.dll','/r:System.Web.Extensions.dll')
$compilerArgs = @('/nologo','/utf8output','/optimize+','/platform:x64','/target:winexe',('/win32manifest:' + (Join-Path $PSScriptRoot 'app.manifest')),('/out:' + (Join-Path $output 'ClaudeRecoveryTool.exe'))) + $references + $sources
& $compiler @compilerArgs
if ($LASTEXITCODE -ne 0) { throw 'Application compilation failed.' }
if ($Tests) {
    $testArgs = @('/nologo','/utf8output','/optimize+','/platform:x64','/target:exe','/main:ClaudeRecovery.Tests',('/out:' + (Join-Path $output 'ClaudeRecoveryTests.exe'))) + $references + $sources + (Join-Path $PSScriptRoot 'Tests.cs')
    & $compiler @testArgs
    if ($LASTEXITCODE -ne 0) { throw 'Test compilation failed.' }
}
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $output 'ClaudeRecoveryTool.exe')
