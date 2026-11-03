param(
    [string]$Executable = (Join-Path $PSScriptRoot '../../target/release/llmghidra-workbench.exe'),
    [string]$Elf = (Join-Path $PSScriptRoot '../../../temp_data/egui-workbench/acceptance/sample.elf')
)
$ErrorActionPreference = 'Stop'
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = [IO.Path]::GetFullPath($Executable)
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.ArgumentList.Add('--serve')
$start.ArgumentList.Add([IO.Path]::GetFullPath($Elf))
$process = [Diagnostics.Process]::Start($start)
$outputTask = $process.StandardOutput.ReadToEndAsync()
$errorTask = $process.StandardError.ReadToEndAsync()
$requests = @(
    @{id=1; method='metadata'},
    @{id=2; method='segments'},
    @{id=3; method='functions'; count=1; offset=1},
    @{id=4; method='read'; address='0x402000'; count=16},
    @{id=5; method='disassemble'; address='0x401000'; count=7},
    @{id=6; method='analyze'; address='0x401000'},
    @{id=7; method='analyze'; address='0x401000'; limits=@{instructions=2}},
    @{id=8; method='read'; address='0xffffffffffffffff'; count=32},
    @{id=9; method='analyze'; address='0x401040'}
)
foreach ($request in $requests) { $process.StandardInput.WriteLine(($request | ConvertTo-Json -Compress -Depth 6)) }
$process.StandardInput.Close()
if (-not $process.WaitForExit(15000)) {
    $process.Kill()
    throw 'Protocol process exceeded 15 second acceptance deadline'
}
if ($process.ExitCode -ne 0) { throw $errorTask.Result }
$responses = @{}
foreach ($line in ($outputTask.Result -split "`n")) {
    if ($line.Trim()) { $response = $line | ConvertFrom-Json; $responses[[int]$response.id] = $response }
}
if ($responses.Count -ne 9) { throw "Expected 9 correlated replies, found $($responses.Count)" }
if ($responses[1].result.machine -ne 183) { throw 'Metadata mismatch' }
if ($responses[2].result.segments.Count -ne 2) { throw 'Segment mismatch' }
if ($responses[3].result.functions.Count -ne 1) { throw 'Function pagination mismatch' }
if ($responses[4].result.bytes -ne '48656c6c6f20416e64726f6964210000') { throw 'Virtual read mismatch' }
if ($responses[5].result.Count -ne 7) { throw 'Disassembly count mismatch' }
if ($responses[6].result.blocks.Count -ne 3 -or $responses[6].result.instructions.Count -ne 7) { throw 'CFG mismatch' }
if (-not $responses[7].result.partial) { throw 'Instruction budget not enforced' }
if (-not $responses[8].error) { throw 'Out-of-range read not rejected' }
if ($responses[9].result.instructions.Count -ne 2) { throw 'Concurrent helper analysis mismatch' }
'JSONL acceptance: 9 replies passed (metadata, segments, functions, read, disassemble, CFG, budget, invalid VA, second function).'
