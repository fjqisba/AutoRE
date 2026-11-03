#Requires -Version 7.0
param([switch]$UseProxy)
$ErrorActionPreference='Stop'
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$version='16.1.0'
$name="windows_10_cmake_Release_Graphviz-$version-win64.zip"
$base="https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/$version"
$download=Join-Path $projectRoot 'temp_data/bootstrap/graphviz'
$install=Join-Path $projectRoot "toolchains/graphviz-$version"
New-Item -ItemType Directory -Force $download,$install|Out-Null
$webArgs=@{TimeoutSec=60}
if($UseProxy){$webArgs.Proxy='http://127.0.0.1:7897'}
$archive=Join-Path $download $name
if(-not(Test-Path $archive)){Invoke-WebRequest "$base/$name" -OutFile $archive @webArgs}
$checksum=(Invoke-WebRequest "$base/$name.sha256" @webArgs).Content
if($checksum -is [byte[]]){$checksum=[Text.Encoding]::UTF8.GetString($checksum)}
$expected=([regex]::Match($checksum,'[0-9a-fA-F]{64}')).Value.ToLowerInvariant()
$actual=(Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if(-not $expected -or $actual-ne $expected){throw 'Graphviz 下载哈希不符'}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=[IO.Compression.ZipFile]::OpenRead($archive)
try{
    foreach($entry in $zip.Entries){
        # 只部署运行工具与许可证。不会提取或生成任何 PNG 文档资源。
        $path=$entry.FullName.Replace('\','/')
        if($path.EndsWith('/') -or $path-match '(?i)\.png$'){continue}
        $parts=$path.Split('/')
        $relative=if($parts[0]-match '^Graphviz'){($parts|Select-Object -Skip 1)-join '/'}else{$path}
        if($relative-notmatch '^(bin|lib)/' -and $relative-notmatch '(?i)(license|copying|notice)'){continue}
        $destination=[IO.Path]::GetFullPath((Join-Path $install $relative))
        if(-not $destination.StartsWith($install+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw '归档路径越界'}
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))|Out-Null
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$destination,$true)
    }
}finally{$zip.Dispose()}
$dot=Join-Path $install 'bin/dot.exe'
if(-not(Test-Path $dot)){throw 'Graphviz 归档中未找到 dot.exe'}
$configPath=Join-Path $projectRoot 'toolchains/local.json'
$config=Get-Content $configPath -Raw|ConvertFrom-Json
$config|Add-Member -NotePropertyName graphviz_dot -NotePropertyValue $dot -Force
$config|ConvertTo-Json -Depth 6|Set-Content $configPath -Encoding utf8
[ordered]@{version=$version;source="$base/$name";sha256=$actual;output_formats=@('dot','svg')}|ConvertTo-Json|
    Set-Content (Join-Path $install 'nereus-package.json') -Encoding utf8
& $dot -V
if($LASTEXITCODE-ne 0){throw 'Graphviz 无法启动'}
