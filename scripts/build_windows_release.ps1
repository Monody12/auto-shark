[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$WorkDirectory,
    [string]$IsccPath,
    [switch]$RequireInstaller
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $ProjectRoot
try {
    $Version = (& uv version --short).Trim()
    if (-not $Version) {
        throw "Could not determine the project version."
    }
    if (-not $OutputDirectory) {
        $OutputDirectory = Join-Path $env:LOCALAPPDATA "AutoShark\releases\$Version"
    }
    if (-not $WorkDirectory) {
        $WorkDirectory = Join-Path $env:LOCALAPPDATA "AutoShark\release-build\$Version"
    }
    $OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
    $WorkDirectory = [System.IO.Path]::GetFullPath($WorkDirectory)
    New-Item -ItemType Directory -Force -Path $OutputDirectory, $WorkDirectory | Out-Null
    Get-ChildItem -LiteralPath $OutputDirectory -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -in @(
                "AutoShark-Windows-x64-Setup.exe",
                "AutoShark-Windows-x64-Portable.zip",
                "SHA256SUMS",
                ".gitignore"
            ) -or $_.Name -like "auto_shark-*.whl" -or $_.Name -like "auto_shark-*.tar.gz"
        } |
        Remove-Item -Force

    $PyInstallerWork = Join-Path $WorkDirectory "pyinstaller-work"
    $PyInstallerDist = Join-Path $WorkDirectory "pyinstaller-dist"
    $PortableStage = Join-Path $WorkDirectory "portable-stage"
    foreach ($Target in @($PyInstallerWork, $PyInstallerDist, $PortableStage)) {
        if (Test-Path -LiteralPath $Target) {
            Remove-Item -LiteralPath $Target -Recurse -Force
        }
    }

    & uv run --no-sync pyinstaller scripts/autoshark.spec --noconfirm --clean `
        --workpath $PyInstallerWork --distpath $PyInstallerDist
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed with exit code $LASTEXITCODE."
    }

    $BundleSource = Join-Path $PyInstallerDist "AutoShark"
    $PortableRoot = Join-Path $PortableStage "AutoShark"
    Copy-Item -LiteralPath $BundleSource -Destination $PortableRoot -Recurse
    Copy-Item -LiteralPath "LICENSE" -Destination $PortableRoot
    Copy-Item -LiteralPath "THIRD_PARTY_NOTICES.md" -Destination $PortableRoot
    Copy-Item -LiteralPath "scripts\README-WINDOWS.txt" `
        -Destination (Join-Path $PortableRoot "README.txt")

    $PortableZip = Join-Path $OutputDirectory "AutoShark-Windows-x64-Portable.zip"
    Compress-Archive -LiteralPath $PortableRoot -DestinationPath $PortableZip `
        -CompressionLevel Optimal -Force

    if (-not $IsccPath) {
        $Command = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
        if ($Command) {
            $IsccPath = $Command.Source
        } else {
            foreach ($Candidate in @(
                "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
                "$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe",
                "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
            )) {
                if (Test-Path -LiteralPath $Candidate) {
                    $IsccPath = $Candidate
                    break
                }
            }
        }
    }

    $InstallerBuilt = $false
    if ($IsccPath -and (Test-Path -LiteralPath $IsccPath)) {
        $VersionParts = @($Version.Split('.'))
        while ($VersionParts.Count -lt 4) {
            $VersionParts += "0"
        }
        $VersionInfo = ($VersionParts[0..3] -join ".")
        & $IsccPath `
            "/DMyAppVersion=$Version" `
            "/DMyVersionInfo=$VersionInfo" `
            "/DSourceDir=$PortableRoot" `
            "/DReleaseDir=$OutputDirectory" `
            "scripts\windows_installer.iss"
        if ($LASTEXITCODE -ne 0) {
            throw "Inno Setup failed with exit code $LASTEXITCODE."
        }
        $InstallerBuilt = $true
    } elseif ($RequireInstaller) {
        throw "Inno Setup 6 (ISCC.exe) is required to build the installer."
    } else {
        Write-Warning "Inno Setup 6 was not found; the portable package was built only."
    }

    & uv build --out-dir $OutputDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "uv build failed with exit code $LASTEXITCODE."
    }

    # uv may place a helper .gitignore in an output directory. It is useful for
    # a source checkout but is not a release asset or part of its checksum set.
    $GeneratedIgnore = Join-Path $OutputDirectory ".gitignore"
    if (Test-Path -LiteralPath $GeneratedIgnore) {
        Remove-Item -LiteralPath $GeneratedIgnore -Force
    }

    $ChecksumPath = Join-Path $OutputDirectory "SHA256SUMS"
    $ChecksumLines = Get-ChildItem -LiteralPath $OutputDirectory -File |
        Where-Object Name -ne "SHA256SUMS" |
        Sort-Object Name |
        ForEach-Object {
            $Hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "$Hash  $($_.Name)"
        }
    Set-Content -LiteralPath $ChecksumPath -Value $ChecksumLines -Encoding ascii

    [pscustomobject]@{
        Version = $Version
        OutputDirectory = $OutputDirectory
        Portable = $PortableZip
        InstallerBuilt = $InstallerBuilt
        Checksums = $ChecksumPath
    } | ConvertTo-Json
} finally {
    Pop-Location
}
