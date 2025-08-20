param(
    [string]$BuildType = "Release",   
    [switch]$RegenStub,               
    [switch]$Purge                   
)

$ErrorActionPreference = "Stop"

function Get-VsDevCmdPrefix {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    $vsPath = $null
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null
    }
    if (-not $vsPath) {
        $candidate = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Microsoft Visual Studio" `
            -Recurse -File -Filter "VsDevCmd.bat" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($candidate) { return "`"$($candidate.FullName)`" -arch=x64 && " } else { return "" }
    }
    $vsDevCmd = Join-Path $vsPath "Common7\Tools\VsDevCmd.bat"
    if (Test-Path $vsDevCmd) { return "`"$vsDevCmd`" -arch=x64 && " }
    return ""
}

Push-Location $PSScriptRoot
try {
    
    New-Item -ItemType Directory -Force -Path ".\tools"       | Out-Null
    New-Item -ItemType Directory -Force -Path ".\obj\packer"  | Out-Null
    if ($RegenStub) {
        New-Item -ItemType Directory -Force -Path ".\obj\stub" | Out-Null
        New-Item -ItemType Directory -Force -Path ".\bin"      | Out-Null
    }

    #
    $optFlags = "/O2"
    $linkIncr = "/INCREMENTAL:NO"
    if ($BuildType -ieq "Debug") { $optFlags = "/Od /Zi"; $linkIncr = "" }

    $tc = Get-VsDevCmdPrefix
    if (-not $tc) { Write-Host "(!) VsDevCmd.bat not found; assuming cl.exe is available..." -ForegroundColor Yellow }

    if ($RegenStub) {
        $stubCmd = $tc + 'chcp 65001 >NUL && cl /nologo /EHsc ' + $optFlags + ' /utf-8 /std:c++17 ' +
                   '/Fo".\obj\stub\\" /Fd".\obj\stub\vc.pdb" ' +
                   'stub_main.cpp aesgcm.cpp /Fe:.\bin\stub_template.exe ' +
                   '/link /SUBSYSTEM:WINDOWS ' + $linkIncr + ' Bcrypt.lib Shell32.lib User32.lib'
        Write-Host "==> Compile stub: $stubCmd"
        & cmd /c $stubCmd
        if ($LASTEXITCODE -ne 0) { throw "Stub compilation failed (code $LASTEXITCODE)" }

        $regenBat = Join-Path $PSScriptRoot "regenstub.bat"
        if (-not (Test-Path $regenBat)) { throw "regenstub.bat not found. Place it in the project root." }

        Write-Host "==> Regenerate stub_bytes.h"
        & cmd /c "`"$regenBat`""
        if ($LASTEXITCODE -ne 0) { throw "regenstub.bat failed (code $LASTEXITCODE)" }
    }

    if (-not (Test-Path (Join-Path $PSScriptRoot "stub_bytes.h"))) {
        throw "stub_bytes.h not found. Run .\build.ps1 -RegenStub 或先手動執行 regenstub.bat"
    }

    $packerCmd = $tc + 'chcp 65001 >NUL && cl /nologo /EHsc ' + $optFlags + ' /utf-8 /std:c++17 ' +
                 '/Fo".\obj\packer\\" /Fd".\obj\packer\vc.pdb" ' +
                 'packer.cpp aesgcm.cpp /Fe:.\tools\packer.exe /link ' + $linkIncr + ' Bcrypt.lib'
    Write-Host "==> Compile packer: $packerCmd"
    & cmd /c $packerCmd
    if ($LASTEXITCODE -ne 0) { throw "Packer compilation failed (code $LASTEXITCODE)" }

 Write-Host "==> Built: .\tools\packer.exe"





}
finally {
    if ($Purge) {
        Write-Host "==> Cleaning artifacts: .\obj (and .\bin if存在)"
        Remove-Item -Recurse -Force ".\obj" -ErrorAction SilentlyContinue
        if (Test-Path ".\bin") { Remove-Item -Recurse -Force ".\bin" -ErrorAction SilentlyContinue }
    }
    Pop-Location
}
