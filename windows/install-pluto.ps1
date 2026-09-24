<#
.SYNOPSIS
  Set up Pluto (tscmoo's Brood War AI) for LOCAL games on StarCraft: Brood War 1.16.1.

.DESCRIPTION
  Downloads BWAPI 4.4.0 and the Pluto CoG 2026 release (both sha256-checked),
  installs them into your StarCraft 1.16.1 folder, and points bwapi.ini at
  pluto.dll. You then start StarCraft through Chaoslauncher.

  This is for 1.16.1 only. StarCraft: Remastered / Battle.net is refused:
  BWAPI does not support it, and running bots on the ladder breaks
  Blizzard's terms.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File install-pluto.ps1 -StarCraftDir "C:\Games\Starcraft"

.EXAMPLE
  # Pluto (Zerg) vs the built-in AI (Protoss) on a random map, started automatically
  .\install-pluto.ps1 -StarCraftDir "C:\Games\Starcraft" -Race Zerg -EnemyRace Protoss -AutoStart
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $StarCraftDir,
  [ValidateSet('Zerg', 'Terran', 'Protoss', 'Random')] [string] $Race = 'Random',
  [ValidateSet('Zerg', 'Terran', 'Protoss', 'Random', 'Default')] [string] $EnemyRace = 'Random',
  # BWAPI map glob, relative to the StarCraft folder
  [string] $Map = 'maps/(?)*.sc?',
  # Start a game against the built-in AI without clicking through menus
  [switch] $AutoStart,
  [switch] $Windowed,
  # Time thread counts once on this machine (~2-4 min), writes pluto/pluto_config.json
  [switch] $Bench
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is very slow with the progress bar

$BwapiUrl  = 'https://github.com/bwapi/bwapi/releases/download/v4.4.0/BWAPI.7z'
$BwapiSha  = 'e6d1abeff2a9b31886d9ade15c5c783a32f7e973f1f0e7137911f3d083fa72e2'
$PlutoUrl  = 'https://github.com/tscmoo/pluto/releases/download/cog2026-2578600/pluto-cog2026-2578600.zip'
$PlutoSha  = 'd4e2225446f5048e131065357173952f0286586da77ebb8bddf7fc766c3844a5'

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

# --- 1. StarCraft 1.16.1 -----------------------------------------------------
Step "Checking StarCraft in $StarCraftDir"
$exe = Join-Path $StarCraftDir 'StarCraft.exe'
if (-not (Test-Path $exe)) { Fail "StarCraft.exe not found in $StarCraftDir" }
$ver = (Get-Item $exe).VersionInfo
$v = '{0}.{1}.{2}' -f $ver.FileMajorPart, $ver.FileMinorPart, $ver.FileBuildPart
if ($v -ne '1.16.1') {
  Fail ("StarCraft.exe is version $v. Pluto/BWAPI 4.4.0 need Brood War 1.16.1. " +
        "Remastered (1.18+) / Battle.net is not supported.")
}
if (-not (Test-Path (Join-Path $StarCraftDir 'BrooDat.mpq'))) { Fail 'BrooDat.mpq missing: Brood War expansion is required.' }

# --- 2. CPU / OS -------------------------------------------------------------
Step 'Checking CPU (AVX2 required, AVX-VNNI recommended)'
Add-Type -Namespace Native -Name K32 -MemberDefinition '[DllImport("kernel32.dll")] public static extern bool IsProcessorFeaturePresent(uint f);'
if (-not [Environment]::Is64BitOperatingSystem) { Fail 'pluto_infer.exe is 64-bit: a 64-bit Windows is required.' }
if (-not [Native.K32]::IsProcessorFeaturePresent(40)) {   # PF_AVX2_INSTRUCTIONS_AVAILABLE
  Fail 'This CPU has no AVX2 (needs Intel Haswell 2013+ or any AMD Zen).'
}
$cores = (Get-CimInstance Win32_Processor | Measure-Object NumberOfCores -Sum).Sum
if ($cores -lt 6) { Write-Warning "$cores cores: Pluto recommends 6+. Games will run slower (the bot does not play worse)." }

# --- 3. Downloads ------------------------------------------------------------
$tmp = Join-Path $env:TEMP 'pluto-setup'
New-Item -ItemType Directory -Force $tmp | Out-Null
function Get-Checked($url, $sha) {
  $out = Join-Path $tmp (Split-Path $url -Leaf)
  if (-not (Test-Path $out) -or (Get-FileHash $out -Algorithm SHA256).Hash -ne $sha.ToUpper()) {
    Step "Downloading $(Split-Path $url -Leaf)"
    Invoke-WebRequest $url -OutFile $out -UseBasicParsing
  }
  $h = (Get-FileHash $out -Algorithm SHA256).Hash
  if ($h -ne $sha.ToUpper()) { Remove-Item $out; Fail "sha256 mismatch for $out ($h)" }
  $out
}
$bwapi7z  = Get-Checked $BwapiUrl $BwapiSha
$plutoZip = Get-Checked $PlutoUrl $PlutoSha

# --- 4. BWAPI 4.4.0 ----------------------------------------------------------
Step 'Unpacking BWAPI 4.4.0'
$bw = Join-Path $tmp 'bwapi'
if (Test-Path $bw) { Remove-Item -Recurse -Force $bw }
New-Item -ItemType Directory $bw | Out-Null
$sevenZip = @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($sevenZip) {
  & $sevenZip x -y "-o$bw" $bwapi7z 'Release_Binary\*' | Out-Null
} else {
  # Windows 10 1803+ ships bsdtar (libarchive), which reads .7z
  tar -xf $bwapi7z -C $bw 'Release_Binary/Starcraft' 'Release_Binary/Chaoslauncher' 2>$null
}
$rel = Join-Path $bw 'Release_Binary'
if (-not (Test-Path (Join-Path $rel 'Starcraft\bwapi-data\BWAPI.dll'))) {
  Fail "Could not unpack BWAPI.7z. Install 7-Zip (https://www.7-zip.org) and re-run, or run BWAPI_Setup.exe from https://github.com/bwapi/bwapi/releases/tag/v4.4.0"
}

$data = Join-Path $StarCraftDir 'bwapi-data'
$ini  = Join-Path $data 'bwapi.ini'
if (Test-Path $ini) { Copy-Item $ini "$ini.bak-$(Get-Date -Format yyyyMMddHHmmss)" }
Step "Installing BWAPI into $StarCraftDir"
Copy-Item -Recurse -Force (Join-Path $rel 'Starcraft\*') $StarCraftDir
$chaos = Join-Path $StarCraftDir 'Chaoslauncher'
Copy-Item -Recurse -Force (Join-Path $rel 'Chaoslauncher') $StarCraftDir

# --- 5. Pluto ----------------------------------------------------------------
Step 'Installing Pluto into bwapi-data\AI'
$ai = Join-Path $data 'AI'
New-Item -ItemType Directory -Force $ai, (Join-Path $data 'read'), (Join-Path $data 'write') | Out-Null
Expand-Archive -Force $plutoZip $ai
foreach ($f in 'pluto.dll', 'pluto\pluto_infer.exe', 'pluto\pluto_weights.bin') {
  if (-not (Test-Path (Join-Path $ai $f))) { Fail "missing $f after unpacking" }
}
# unsigned binaries downloaded from the internet: drop the Mark-of-the-Web so SmartScreen doesn't block the engine
Get-ChildItem -Recurse $ai | Unblock-File

# --- 6. bwapi.ini ------------------------------------------------------------
Step 'Configuring bwapi.ini'
function Set-Ini($text, $key, $value) {
  $rx = "(?m)^(\s*$([regex]::Escape($key))\s*=).*$"
  if ($text -notmatch $rx) { Fail "bwapi.ini has no '$key' line" }
  ([regex]$rx).Replace($text, "`${1} $value", 1)
}
$t = Get-Content -Raw $ini
$t = Set-Ini $t 'ai' 'bwapi-data/AI/pluto.dll'
$t = Set-Ini $t 'race' $Race
$t = Set-Ini $t 'enemy_race' $EnemyRace
$t = Set-Ini $t 'map' $Map
$t = Set-Ini $t 'auto_menu' ($(if ($AutoStart) { 'SINGLE_PLAYER' } else { 'OFF' }))
$t = Set-Ini $t 'windowed' ($(if ($Windowed) { 'ON' } else { 'OFF' }))
Set-Content -NoNewline -Encoding ASCII $ini $t

if ($Bench) {
  Step 'Benchmarking inference threads (2-4 minutes)'
  Push-Location (Join-Path $ai 'pluto')
  try { & .\pluto_infer.exe --bench } finally { Pop-Location }
}

# --- 7. Launcher shortcut ----------------------------------------------------
$launcher = Join-Path $chaos 'Chaoslauncher.exe'
$lnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Pluto (Chaoslauncher).lnk'
$sh = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
$sh.TargetPath = $launcher; $sh.WorkingDirectory = $chaos; $sh.Save()

Write-Host ''
Write-Host 'Done. To play:' -ForegroundColor Green
Write-Host "  1. Run '$lnk' (as administrator the first time)."
Write-Host "  2. In Chaoslauncher > Settings, set the StarCraft path to $exe if it is not detected."
Write-Host "  3. Tick 'BWAPI 4.4.0 Injector [RELEASE]' (and 'W-MODE' for a window), then Start."
if ($AutoStart) {
  Write-Host "  4. A game vs the built-in AI starts by itself ($Race vs $EnemyRace, maps: $Map)."
} else {
  Write-Host '  4. Single Player > Expansion > Play Custom > pick a map, add a Computer opponent, Start Game.'
}
Write-Host "Pluto says 'Pluto online (...). gl hf!' when it starts. Logs: pluto.log, pluto_infer.log in $StarCraftDir."
Write-Host "Win-probability overlay: set BWRL_DRAW=1 before starting Chaoslauncher:  `$env:BWRL_DRAW=1; & '$launcher'"
