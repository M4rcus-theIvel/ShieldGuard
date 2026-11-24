param(
    [Parameter(Mandatory = $true)]
    [string]$Publisher,
    [Parameter(Mandatory = $true)]
    [string]$GitHubUser,
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [string]$ExePath = "..\..\dist\ShieldGuard.exe"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $ExePath)) {
    throw "Cannot find $ExePath. Build ShieldGuard.exe first or pass -ExePath."
}

$sha256 = (Get-FileHash -Path $ExePath -Algorithm SHA256).Hash
$pkgId = "$Publisher.ShieldGuard"
$outDir = Join-Path $PSScriptRoot "manifests\$Version"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$installerUrl = "https://github.com/$GitHubUser/ShieldGuard/releases/download/v$Version/ShieldGuard.exe"

@"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.version.1.6.0.schema.json
PackageIdentifier: $pkgId
PackageVersion: $Version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
"@ | Set-Content -Path (Join-Path $outDir "$pkgId.yaml") -Encoding UTF8

@"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.installer.1.6.0.schema.json
PackageIdentifier: $pkgId
PackageVersion: $Version
InstallerType: portable
Commands:
  - shieldguard
Installers:
  - Architecture: x64
    InstallerUrl: $installerUrl
    InstallerSha256: $sha256
ManifestType: installer
ManifestVersion: 1.6.0
"@ | Set-Content -Path (Join-Path $outDir "$pkgId.installer.yaml") -Encoding UTF8

@"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.defaultLocale.1.6.0.schema.json
PackageIdentifier: $pkgId
PackageVersion: $Version
PackageLocale: en-US
Publisher: $Publisher
PublisherUrl: https://github.com/$GitHubUser
PackageName: ShieldGuard
PackageUrl: https://github.com/$GitHubUser/ShieldGuard
License: MIT
ShortDescription: Windows anti-malware, stealth crypto-miner, persistence, and Defender exclusion scanner.
Tags:
  - antivirus
  - malware
  - security
  - crypto-miner
  - windows-defender
ManifestType: defaultLocale
ManifestVersion: 1.6.0
"@ | Set-Content -Path (Join-Path $outDir "$pkgId.locale.en-US.yaml") -Encoding UTF8

Write-Output "[OK] WinGet manifests generated in: $outDir"
Write-Output "SHA-256: $sha256"
Write-Output "Validate with: winget validate --manifest `"$outDir`""
