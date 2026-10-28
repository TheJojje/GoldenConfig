<#
.SYNOPSIS
  goldencheck - jämför IOS-XE running-config mot "golden"-profiler (LÄSLÄGE).

.DESCRIPTION
  Ändrar ALDRIG något på enheterna. I liveläge körs enbart 'show running-config'.
  Kräver ingen installation: Windows PowerShell 5.1 (eller PowerShell 7) räcker,
  plus plink.exe (PuTTY) eller Windows OpenSSH (ssh.exe) för liveläge.

.EXAMPLE
  # Startmeny: välj hostlista (grupper), en specifik switch + template, eller cacha värdnycklar (meny 3)
  .\goldencheck.ps1

.EXAMPLE
  # Utan meny: en grupp, flera grupper, alla enheter
  .\goldencheck.ps1 -Group access
  .\goldencheck.ps1 -Group access,dc
  .\goldencheck.ps1 -All

.EXAMPLE
  # En specifik switch (ur inventory eller ny IP/host) mot vald template
  .\goldencheck.ps1 -Target 10.0.0.55 -Template access-switch
  .\goldencheck.ps1 -Device sw01 -Template dc-switch

.EXAMPLE
  # Offline, mot sparade konfigfiler (samples\<enhetsnamn>.cfg)
  .\goldencheck.ps1 -Offline samples -Group access

.NOTES
  CSV: en fil med enbart avvikande konfiguration (MISSING / EXTRA / FORBIDDEN) skrivs automatiskt till
  reports\ (stäng av med -NoCsv, eget namn med -Csv). Med -WithActions läggs föreslagna kommandon,
  portar utan profil och enheter som inte kunde skannas till. Inget körs någonsin automatiskt.
  Enheter som inte kunde skannas kommer med som FEL-rader i CSV:n, och hela konsolutskriften sparas som .txt
  bredvid CSV:n. Med -Xlsx skrivs samma innehåll även som en riktig .xlsx-fil (bredvid CSV:n) med
  kolumnbredd anpassad efter innehållet (Excel har ingen formatering i en CSV-fil). Med -SaveConfigs
  sparas de hämtade konfigurationerna (innehåller hashar/nycklar: känsligt!) i
  reports\configs_<tid>\ och kan köras om offline (-Offline <mapp>) utan att röra switcharna.
  -CacheHostKeys: (plink) visar varje switchs fingeravtryck och låter dig godkänna innan värdnyckeln cachas, så att
  -batch-körningarna sedan fungerar. Ingen konfig hämtas. Resultatet loggas i reports\hostkeys_<tid>.txt.
  Lägg till -AcceptAllHostKeys för att godkänna alla utan att fråga per enhet (skalbart för många switchar;
  TOFU-risk - spara/jämför hostkeys_<tid>.txt vid behov). Samma sak nås via startmenyns val 3.
  Exit-kod: 0 = inga avvikelser, 1 = avvikelser/fel, 2 = felaktigt argument.
  Användare/lösenord: miljövariablerna NET_USER / NET_PASS, annars prompt.
  Lösenord behövs inte om enheten har 'key' (nyckelinloggning).
#>
[CmdletBinding()]
param(
    [string]$Inventory,
    [string]$Profiles,
    [string]$Switches,
    [string]$GoldenDir,
    [string[]]$Device,
    [string[]]$Group,
    [switch]$All,
    [string]$Target,
    [string]$Template,
    [string]$Offline,
    [ValidateSet('plink', 'ssh')][string]$Transport,
    [string]$Plink = 'plink.exe',
    [string]$Json,
    [string]$Csv,
    [switch]$NoCsv,
    [switch]$WithActions,
    [switch]$Xlsx,
    [switch]$SaveConfigs,
    [switch]$CacheHostKeys,
    [switch]$AcceptAllHostKeys
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Skriptets katalog. $PSScriptRoot är inte alltid ifylld i Windows PowerShell 5.1
# (t.ex. i param-block), så det finns en reservväg via $MyInvocation.
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $ScriptDir) { $ScriptDir = (Get-Location).Path }
if (-not $Inventory) { $Inventory = Join-Path $ScriptDir 'inventory.psd1' }
if (-not $Profiles) { $Profiles = Join-Path $ScriptDir 'profiles.psd1' }
if (-not $Switches) { $Switches = Join-Path $ScriptDir 'switches.csv' }
if (-not $GoldenDir) { $GoldenDir = Join-Path $ScriptDir 'golden' }
# Angavs -Inventory/-Profiles/-Switches/-GoldenDir explicit på kommandoraden? (annars är de bara
# standardvärden, och filen/mappen får saknas utan att det är ett fel - den enkla formen är då av.)
$InventoryExplicit = $PSBoundParameters.ContainsKey('Inventory')
$ProfilesExplicit  = $PSBoundParameters.ContainsKey('Profiles')
$SwitchesExplicit  = $PSBoundParameters.ContainsKey('Switches')
$GoldenDirExplicit = $PSBoundParameters.ContainsKey('GoldenDir')

# 'powershell -File ... -Group access,dc' skickar "access,dc" som EN sträng: dela upp själva
if ($Group)  { $Group  = @($Group  | ForEach-Object { $_ -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
if ($Device) { $Device = @($Device | ForEach-Object { $_ -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }

$Severity = @{ FORBIDDEN = 'hög'; MISSING = 'medel'; EXTRA = 'låg'; NO_PROFILE = 'info' }
# Toppnivårader som aldrig räknas som "extra" i global konfig (IOS-XE-boilerplate). Lägg egna i 'extra_ignore' i profilen.
$DefaultExtraIgnore = @(
    '^Building configuration', '^Current configuration', '^!', '^version \d', '^end$',
    '^boot-(start|end)-marker$', '^boot system ',
    '^(class-map|policy-map) .*system-cpp', '^class-map match-any non-client-nrt-class$',
    '^switch \d+ provision ', '^crypto pki ', '^vrf definition Mgmt-vrf$', '^call-home$'
)
$PhysicalRx = '^(Fast|Gigabit|TwoGigabit|FiveGigabit|TenGigabit|TwentyFiveGigE|FortyGigabit|HundredGig)Ethernet\S+$'

# --------------------------------------------------------------------------
# Hjälpfunktioner
# --------------------------------------------------------------------------
function Resolve-FullPath([string]$Path) {
    # .NET-API:er använder processens katalog, inte PowerShells aktuella plats
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Norm([string]$s) {
    # trimma och slå ihop whitespace
    return [regex]::Replace($s.Trim(), '\s+', ' ')
}

function Test-Rx([string]$Text, [string]$Pattern) {
    # Skiftlägeskänsligt som Pythons re.search (till skillnad från PowerShells -match)
    return [regex]::IsMatch($Text, $Pattern)
}

function Get-List($Table, [string]$Key) {
    if ($null -ne $Table -and $Table.ContainsKey($Key) -and $null -ne $Table[$Key]) { return @($Table[$Key]) }
    return @()
}

function Merge-Hash([hashtable]$Base, [hashtable]$Over) {
    $r = @{}
    if ($Base) { foreach ($k in $Base.Keys) { $r[$k] = $Base[$k] } }
    if ($Over) { foreach ($k in $Over.Keys) { $r[$k] = $Over[$k] } }
    return $r
}

function Sort-Ordinal($Items) {
    # Kodpunktsordning (som Pythons sorted) - inte kulturberoende
    $l = New-Object 'System.Collections.Generic.List[string]'
    foreach ($i in $Items) { $l.Add([string]$i) }
    $l.Sort([System.StringComparer]::Ordinal)
    return , $l
}

function New-Set($Items) {
    $s = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($i in $Items) { [void]$s.Add([string]$i) }
    return , $s
}

function New-Finding([string]$Dev, [string]$Scope, [string]$Prof, [string]$Kind, [string]$Line, [string]$Context = '') {
    # Context = konfigläget raden hör hemma i (t.ex. "interface Gi1/0/2"); tomt = global konfig
    return [pscustomobject]@{
        device   = $Dev
        scope    = $Scope
        profile  = $Prof
        kind     = $Kind
        line     = $Line
        severity = $Severity[$Kind]
        context  = $Context
    }
}

function Test-LinePresent([string]$Golden, $Actual) {
    # 're:<regex>' matchar minst en rad, annars exakt matchning
    if ($Golden.StartsWith('re:')) {
        $rx = $Golden.Substring(3).Trim()
        foreach ($a in $Actual) { if (Test-Rx $a $rx) { return $true } }
        return $false
    }
    return $Actual.Contains($Golden)
}

function Test-MatchesAny([string]$Line, $Patterns) {
    foreach ($p in $Patterns) { if (Test-Rx $Line $p) { return $true } }
    return $false
}

function Expand-Template([string]$Line, [hashtable]$Ctx) {
    # Stöder enkla {{ variabel }}; okänd variabel ger fel (som Jinja2 StrictUndefined)
    $result = $Line
    foreach ($m in [regex]::Matches($Line, '\{\{\s*(\w+)\s*\}\}')) {
        $k = $m.Groups[1].Value
        if (-not $Ctx.ContainsKey($k)) { throw "Odefinierad mallvariabel '$k' i raden: $Line" }
        $result = $result.Replace($m.Value, [string]$Ctx[$k])
    }
    return (Norm $result)
}

# --------------------------------------------------------------------------
# IOS-parser: toppnivårader med direkta barn (indrag)
# --------------------------------------------------------------------------
function ConvertFrom-IosConfig([string]$Text) {
    $objs = New-Object 'System.Collections.Generic.List[object]'
    $cur = $null
    $childIndent = -1
    $inBanner = $false
    $bannerDelim = ''
    $etx = [string][char]3

    foreach ($raw in ($Text -split "\r?\n")) {
        $line = $raw.TrimEnd()

        # Bannertext sträcker sig över flera rader och är inte konfig. Bannern slutar vid slutavgränsaren
        # (^C, tecknet ETX eller startens avgränsare) ELLER vid nästa '!'-rad. Det senare gör att en
        # avgränsare som försvunnit på vägen (t.ex. i SSH-utskriften) inte läcker bannertext som konfigrader.
        if ($inBanner) {
            if ($line.Trim() -eq '!' -or $line.Contains('^C') -or $line.Contains($etx) -or
                ($bannerDelim -ne '' -and $line.Contains($bannerDelim))) {
                $inBanner = $false
                $cur = $null
            }
            continue
        }
        if ($line.Trim() -eq '') { continue }

        if ($line.TrimStart() -eq '!') { $cur = $null; continue }

        if ($line -match '^\s+\S') {
            if ($null -ne $cur) {
                $indent = $line.Length - $line.TrimStart().Length
                if ($cur.Children.Count -eq 0) { $childIndent = $indent }
                if ($indent -le $childIndent) { $cur.Children.Add($line) }
            }
            continue
        }

        # Ny toppnivårad
        $cur = [pscustomobject]@{
            Text     = $line
            Children = (New-Object 'System.Collections.Generic.List[string]')
        }
        $objs.Add($cur)
        $childIndent = -1

        if ($line -match '^banner\s+\S+(?:\s+(.*))?$') {
            $rest = ''
            if ($Matches.ContainsKey(1)) { $rest = [string]$Matches[1] }
            $delim = ''
            $after = $rest
            if ($rest.StartsWith('^C')) { $delim = '^C'; $after = $rest.Substring(2) }
            elseif ($rest.Length -gt 0 -and $rest[0] -eq [char]3) { $delim = $etx; $after = $rest.Substring(1) }
            elseif ($rest.Length -gt 0 -and -not [char]::IsLetterOrDigit($rest[0])) { $delim = [string]$rest[0]; $after = $rest.Substring(1) }
            # hela bannern på en rad (avgränsaren förekommer igen): inget mer att hoppa över
            if ($delim -ne '' -and $after.Contains($delim)) { continue }
            $inBanner = $true
            $bannerDelim = $delim
        }
    }
    return , $objs
}

# --------------------------------------------------------------------------
# Hämta konfig
# --------------------------------------------------------------------------
function Quote-Arg([string]$a) {
    # Windows-kommandoradscitering (CommandLineToArgvW-regler)
    if ($a -eq '') { return '""' }
    if ($a -notmatch '[\s"]') { return $a }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $bs = 0
    foreach ($c in $a.ToCharArray()) {
        if ($c -eq '\') { $bs++ }
        elseif ($c -eq '"') { [void]$sb.Append('\' * ($bs * 2 + 1)); [void]$sb.Append('"'); $bs = 0 }
        else { [void]$sb.Append('\' * $bs); [void]$sb.Append($c); $bs = 0 }
    }
    [void]$sb.Append('\' * ($bs * 2))
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Resolve-Exe([string]$Name) {
    if (Test-Path -LiteralPath $Name -PathType Leaf) { return (Resolve-Path -LiteralPath $Name).Path }
    $beside = Join-Path $ScriptDir $Name
    if (Test-Path -LiteralPath $beside -PathType Leaf) { return $beside }
    $cmd = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    throw "Hittar inte '$Name'. Lägg filen bredvid skriptet, i PATH, eller ange sökväg (-Plink / plink_path)."
}

function Invoke-External([string]$Exe, [string[]]$ArgList, [int]$TimeoutSec = 120, [string]$InputText = '') {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = (($ArgList | ForEach-Object { Quote-Arg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

    try { $p = [System.Diagnostics.Process]::Start($psi) }
    catch { throw "Kunde inte starta ${Exe}: $($_.Exception.Message)" }

    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if ($InputText) { $p.StandardInput.Write($InputText) }
    $p.StandardInput.Close()      # inget interaktivt: ingen prompt får hänga
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch { }
        throw "Timeout ($TimeoutSec s) mot $Exe"
    }
    $p.WaitForExit()
    return [pscustomobject]@{ ExitCode = $p.ExitCode; Out = $outTask.Result; Err = $errTask.Result.Trim() }
}

function Assert-ConfigOutput([string]$Out, [string]$Err) {
    if ($Out.Contains('--More--')) {
        throw "Utskriften innehåller --More-- (pager). Sätt 'length 0' på vty-linjen."
    }
    if (-not [regex]::IsMatch($Out, '(?m)^hostname \S+') -and @($Out -split "\r?\n").Count -lt 20) {
        $e = $Err; if ($e.Length -gt 200) { $e = $e.Substring(0, 200) }
        throw ("Svaret ser inte ut som en running-config (för kort, saknar 'hostname'). " +
               "Kontrollera behörighet (privilege 15) och att exec-kommandon tillåts. stderr: $e")
    }
}

function Get-ConfigOffline([string]$Name, [string]$Folder) {
    $p = Join-Path $Folder "$Name.cfg"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "Hittar inte $p" }
    return [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8)
}

function Get-ConfigPlink([hashtable]$Dev, [string]$User, [string]$Password, [string]$PlinkName) {
    $exe = Resolve-Exe $PlinkName
    $a = @('-ssh', '-batch', '-T', '-l', $User)
    if ($Dev.ContainsKey('port') -and $Dev['port']) { $a += @('-P', [string]$Dev['port']) }
    if ($Dev.ContainsKey('hostkey') -and $Dev['hostkey']) { $a += @('-hostkey', [string]$Dev['hostkey']) }
    if ($Dev.ContainsKey('key') -and $Dev['key']) { $a += @('-i', [string]$Dev['key']) }
    elseif ($Password) { $a += @('-pw', $Password) }
    $a += @([string]$Dev['host'], 'show running-config')

    $r = Invoke-External $exe $a
    if ($r.ExitCode -ne 0) {
        $hint = ''
        if ($r.Err -match '(?i)host ?key') {
            $hint = " (värdnyckeln är inte cachad: anslut en gång manuellt med plink, eller sätt 'hostkey' i inventory)"
        }
        $msg = $r.Err; if (-not $msg) { $msg = 'inget felmeddelande' }
        throw "plink returnerade $($r.ExitCode): $msg$hint"
    }
    Assert-ConfigOutput $r.Out $r.Err
    return $r.Out
}

function Get-ConfigSsh([hashtable]$Dev, [string]$User) {
    $exe = Resolve-Exe 'ssh.exe'
    $a = @('-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15')
    if ($Dev.ContainsKey('port') -and $Dev['port']) { $a += @('-p', [string]$Dev['port']) }
    if ($Dev.ContainsKey('key') -and $Dev['key']) { $a += @('-i', [string]$Dev['key']) }
    if ($Dev.ContainsKey('ssh_options')) { $a += @(Get-List $Dev 'ssh_options' | ForEach-Object { [string]$_ }) }
    $a += @("$User@$($Dev['host'])", 'show running-config')

    $r = Invoke-External $exe $a
    if ($r.ExitCode -ne 0) {
        $hint = ''
        if ($r.Err -match '(?i)host key verification') {
            $hint = " (okänd värdnyckel: anslut en gång manuellt, eller sätt ssh_options = @('-o','StrictHostKeyChecking=accept-new'))"
        }
        elseif ($r.Err -match '(?i)permission denied') {
            $hint = ' (ssh.exe kör i BatchMode: nyckelinloggning krävs, lösenord kan inte anges)'
        }
        $msg = $r.Err; if (-not $msg) { $msg = 'inget felmeddelande' }
        throw "ssh returnerade $($r.ExitCode): $msg$hint"
    }
    Assert-ConfigOutput $r.Out $r.Err
    return $r.Out
}

# --------------------------------------------------------------------------
# Jämförelse
# --------------------------------------------------------------------------
function Test-Global([string]$Name, $Parse, [hashtable]$Gp, [string]$Label, $Out) {
    $top = New-Set ($Parse | ForEach-Object { Norm $_.Text })

    foreach ($req in (Get-List $Gp 'required')) {
        $n = Norm $req
        if (-not (Test-LinePresent $n $top)) { $Out.Add((New-Finding $Name 'global' $Label 'MISSING' $n)) }
    }
    foreach ($pat in (Get-List $Gp 'forbidden')) {
        foreach ($line in (Sort-Ordinal $top)) {
            if (Test-Rx $line $pat) { $Out.Add((New-Finding $Name 'global' $Label 'FORBIDDEN' $line)) }
        }
    }
    # Block, t.ex. "line vty": kontrollera barnraderna under varje matchande förälder
    foreach ($blk in (Get-List $Gp 'blocks')) {
        foreach ($obj in $Parse) {
            if (-not (Test-Rx $obj.Text $blk['parent'])) { continue }
            $kids = New-Set ($obj.Children | ForEach-Object { Norm $_ })
            $scope = Norm $obj.Text
            foreach ($req in (Get-List $blk 'required')) {
                $n = Norm $req
                if (-not (Test-LinePresent $n $kids)) { $Out.Add((New-Finding $Name $scope $Label 'MISSING' $n $scope)) }
            }
            foreach ($pat in (Get-List $blk 'forbidden')) {
                foreach ($k in (Sort-Ordinal $kids)) {
                    if (Test-Rx $k $pat) { $Out.Add((New-Finding $Name $scope $Label 'FORBIDDEN' $k $scope)) }
                }
            }
        }
    }
    Test-GlobalExtra $Name $Parse $Gp $Label $Out
}

function Test-GlobalExtra([string]$Name, $Parse, [hashtable]$Gp, [string]$Label, $Out) {
    # Rader på enheten som golden inte känner till: toppnivårader samt underrader under kända avsnitt (blocks).
    # Slås på med  extra = $true  i den globala profilen; undantag via  extra_ignore  (regex).
    if (-not ($Gp.ContainsKey('extra') -and $Gp['extra'])) { return }
    $ignore = @($DefaultExtraIgnore) + @(Get-List $Gp 'extra_ignore')
    $exact = New-Set @()
    $rxs = New-Object 'System.Collections.Generic.List[string]'
    foreach ($req in (Get-List $Gp 'required')) {
        $n = Norm $req
        if ($n.StartsWith('re:')) { $rxs.Add($n.Substring(3).Trim()) } else { [void]$exact.Add($n) }
    }
    $forb = @(Get-List $Gp 'forbidden')
    $blocks = @(Get-List $Gp 'blocks')

    $topExtra = New-Object 'System.Collections.Generic.List[string]'
    $blkExtra = New-Object 'System.Collections.Generic.List[object]'
    foreach ($obj in $Parse) {
        $t = Norm $obj.Text
        $blk = $null
        foreach ($b in $blocks) { if (Test-Rx $obj.Text $b['parent']) { $blk = $b; break } }

        if ($null -eq $blk) {
            if ($exact.Contains($t) -or (Test-MatchesAny $t $rxs) -or (Test-MatchesAny $t $ignore) -or
                (Test-MatchesAny $t $forb) -or (Test-Rx $t '^interface ')) { continue }
            $topExtra.Add($t)
            continue
        }
        # underrader under ett känt avsnitt
        $bExact = New-Set @()
        $bRx = New-Object 'System.Collections.Generic.List[string]'
        foreach ($req in (Get-List $blk 'required')) {
            $n = Norm $req
            if ($n.StartsWith('re:')) { $bRx.Add($n.Substring(3).Trim()) } else { [void]$bExact.Add($n) }
        }
        $bForb = @(Get-List $blk 'forbidden')
        $bIgn = @(Get-List $blk 'ignore')
        foreach ($k in (Sort-Ordinal (New-Set ($obj.Children | ForEach-Object { Norm $_ })))) {
            if ($bExact.Contains($k) -or (Test-MatchesAny $k $bRx) -or (Test-MatchesAny $k $bForb) -or (Test-MatchesAny $k $bIgn)) { continue }
            $blkExtra.Add([pscustomobject]@{ scope = $t; line = $k })
        }
    }
    foreach ($t in (Sort-Ordinal $topExtra)) { $Out.Add((New-Finding $Name 'global' $Label 'EXTRA' $t '')) }
    foreach ($e in $blkExtra) { $Out.Add((New-Finding $Name $e.scope $Label 'EXTRA' $e.line $e.scope)) }
}

function Select-Rule($Rules, [string]$IfName, [string]$Descr) {
    # Första regeln där alla angivna villkor (name/description) matchar vinner
    foreach ($r in $Rules) {
        $hasName = $r.ContainsKey('name')
        $hasDesc = $r.ContainsKey('description')
        if (-not $hasName -and -not $hasDesc) { continue }
        if ($hasName -and -not (Test-Rx $IfName $r['name'])) { continue }
        if ($hasDesc -and -not (Test-Rx $Descr $r['description'])) { continue }
        return $r
    }
    return $null
}

function Test-Interface([string]$DevName, [string]$IfName, $Children, [string]$ProfName,
                        [hashtable]$Prof, [hashtable]$Ctx, $CommonIgnore, $Out) {
    $local = New-Object 'System.Collections.Generic.List[object]'
    $actual = New-Set ($Children | ForEach-Object { Norm $_ })
    $golden = @(Get-List $Prof 'config' | ForEach-Object { Expand-Template $_ $Ctx })
    $goldenExact = New-Set ($golden | Where-Object { -not $_.StartsWith('re:') })

    # 1. Saknas
    foreach ($g in $golden) {
        if (-not (Test-LinePresent $g $actual)) { $local.Add((New-Finding $DevName $IfName $ProfName 'MISSING' $g "interface $IfName")) }
    }
    # 2. Förbjudet
    foreach ($pat in (Get-List $Prof 'forbidden')) {
        foreach ($a in (Sort-Ordinal $actual)) {
            if (Test-Rx $a $pat) { $local.Add((New-Finding $DevName $IfName $ProfName 'FORBIDDEN' $a "interface $IfName")) }
        }
    }
    # 3. Extra: inte i golden, inte matchad av re:-rad, inte ignorerad
    $goldenRx = @($golden | Where-Object { $_.StartsWith('re:') } | ForEach-Object { $_.Substring(3).Trim() })
    $ignore = @($CommonIgnore) + @(Get-List $Prof 'ignore')
    $forbiddenLines = New-Set ($local | Where-Object { $_.kind -eq 'FORBIDDEN' } | ForEach-Object { $_.line })
    foreach ($a in (Sort-Ordinal $actual)) {
        if ($goldenExact.Contains($a) -or $forbiddenLines.Contains($a)) { continue }
        if (Test-MatchesAny $a $goldenRx) { continue }
        if (Test-MatchesAny $a $ignore) { continue }
        $local.Add((New-Finding $DevName $IfName $ProfName 'EXTRA' $a "interface $IfName"))
    }
    foreach ($f in $local) { $Out.Add($f) }
}

function Test-Device([string]$Name, [hashtable]$Dev, [string]$CfgText, [hashtable]$Prof) {
    $findings = New-Object 'System.Collections.Generic.List[object]'
    $parse = ConvertFrom-IosConfig $CfgText

    # Global
    if ($Dev.ContainsKey('global') -and $Dev['global']) {
        $gname = [string]$Dev['global']
        $gAll = $Prof['global']
        if ($null -eq $gAll -or -not $gAll.ContainsKey($gname)) {
            throw "$($Name): global-profil '$gname' finns inte i profiles.psd1"
        }
        Test-Global $Name $parse $gAll[$gname] "global:$gname" $findings
    }

    # Interfaces
    $commonIgnore = Get-List $Prof 'common_ignore'
    $ifProfiles = $Prof['interface_profiles']
    $rules = Get-List $Dev 'interface_rules'
    $reportUnmatched = $true
    if ($Dev.ContainsKey('report_unmatched')) { $reportUnmatched = [bool]$Dev['report_unmatched'] }

    foreach ($obj in $parse) {
        if (-not (Test-Rx $obj.Text '^interface ')) { continue }
        $ifname = ($obj.Text -split '\s+', 2)[1].Trim()
        $descr = ''
        foreach ($c in $obj.Children) {
            $n = Norm $c
            if ($n.StartsWith('description ')) { $descr = $n.Substring('description '.Length); break }
        }

        $rule = Select-Rule $rules $ifname $descr
        if ($null -eq $rule) {
            if ($reportUnmatched -and (Test-Rx $ifname $PhysicalRx)) {
                $findings.Add((New-Finding $Name $ifname '-' 'NO_PROFILE' 'porten matchar ingen regel' "interface $ifname"))
            }
            continue
        }

        $pname = [string]$rule['profile']
        if ($pname -eq 'IGNORE') { continue }
        if ($null -eq $ifProfiles -or -not $ifProfiles.ContainsKey($pname)) {
            throw "$($Name): interface-profil '$pname' finns inte i profiles.psd1"
        }
        $ifProf = $ifProfiles[$pname]

        $ctx = @{}
        foreach ($src in @($ifProf['vars'], $Dev['vars'], $rule['vars'])) {
            if ($null -ne $src) { foreach ($k in $src.Keys) { $ctx[$k] = $src[$k] } }
        }
        $ctx['interface'] = $ifname
        $ctx['description'] = $descr
        $ctx['host'] = [string]$Dev['host']       # inventory-adress, t.ex. 'ip address {{ host }} 255.255.255.0'
        Test-Interface $Name $ifname $obj.Children $pname $ifProf $ctx $commonIgnore $findings
    }
    return , $findings
}

# --------------------------------------------------------------------------
# Rapportering
# --------------------------------------------------------------------------
function Write-Report($AllFindings, $Errors, $Meta, $ScanInfo) {
    $sym = @{ MISSING = '-'; EXTRA = '+'; FORBIDDEN = '!'; NO_PROFILE = '?' }
    foreach ($dev in $AllFindings.Keys) {
        $findings = $AllFindings[$dev]
        Write-Output ''
        Write-Output ("=== $dev " + ('=' * [Math]::Max(3, 60 - $dev.Length)))
        if ($findings.Count -eq 0) { Write-Output '  OK - inga avvikelser'; continue }

        $byScope = [ordered]@{}
        foreach ($f in $findings) {
            if (-not $byScope.Contains($f.scope)) { $byScope[$f.scope] = New-Object 'System.Collections.Generic.List[object]' }
            $byScope[$f.scope].Add($f)
        }
        foreach ($scope in $byScope.Keys) {
            $items = $byScope[$scope]
            Write-Output "  $scope  (profil: $($items[0].profile))"
            foreach ($f in $items) {
                Write-Output ("    $($sym[$f.kind]) $($f.kind.PadRight(10)) [$($f.severity)] $($f.line)")
            }
        }
    }
    foreach ($dev in $Errors.Keys) {
        Write-Output ''
        Write-Output "=== $dev ==="
        Write-Output "  FEL: $($Errors[$dev])"
    }

    $flat = @(foreach ($k in $AllFindings.Keys) { foreach ($f in $AllFindings[$k]) { $f } })
    Write-Output ''
    Write-Output ('--- Sammanfattning ' + ('-' * 40))
    Write-Output "  Enheter kontrollerade : $($AllFindings.Count)   (fel: $($Errors.Count))"
    foreach ($kind in @('FORBIDDEN', 'MISSING', 'EXTRA', 'NO_PROFILE')) {
        $n = @($flat | Where-Object { $_.kind -eq $kind }).Count
        Write-Output ("  $($kind.PadRight(11)): $n")
    }
    Write-Output '  Teckenförklaring: - saknas, + extra rad, ! förbjuden rad, ? port utan profil'

    # Per enhet: visar att varje enhet faktiskt skannades (och hur stor konfigen var)
    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($n in $Meta.Keys) { $names.Add([string]$n) }
    foreach ($n in $Errors.Keys) { if (-not $names.Contains([string]$n)) { $names.Add([string]$n) } }
    if ($names.Count -ge 2) {
        Write-Output ''
        Write-Output ('--- Per enhet ' + ('-' * 44))
        $w = ($names | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
        foreach ($n in $names) {
            $status = ''
            if ($Errors.Contains($n)) {
                $msg = ([string]$Errors[$n] -split "\r?\n")[0]
                if ($msg.Length -gt 70) { $msg = $msg.Substring(0, 70) + '...' }
                $status = "FEL: $msg"
            }
            elseif ($AllFindings.Contains($n)) {
                $fs = @($AllFindings[$n].ToArray())
                $m = @($fs | Where-Object { $_.kind -eq 'MISSING' }).Count
                $e = @($fs | Where-Object { $_.kind -eq 'EXTRA' }).Count
                $f = @($fs | Where-Object { $_.kind -eq 'FORBIDDEN' }).Count
                $np = @($fs | Where-Object { $_.kind -eq 'NO_PROFILE' }).Count
                if (($m + $e + $f) -eq 0) { $status = 'OK' } else { $status = 'AVVIKER  (saknas {0}, extra {1}, förbjudna {2})' -f $m, $e, $f }
                if ($np -gt 0) { $status += "  [$np port(ar) utan profil]" }
            }
            $rows = ''
            if ($ScanInfo.Contains($n)) { $rows = '   [' + $ScanInfo[$n] + ' konfigrader]' }
            Write-Output ('  {0}  {1}{2}' -f $n.PadRight($w), $status, $rows)
        }

        # Extra rader utanför interface som finns på flera enheter: kandidater för golden eller extra_ignore
        $common = @{}
        foreach ($k in $AllFindings.Keys) {
            foreach ($f in $AllFindings[$k]) {
                if ($f.kind -eq 'EXTRA' -and -not $f.context.StartsWith('interface ')) {
                    $key = $f.line
                    if ($f.scope -ne 'global') { $key = "[$($f.scope)] $($f.line)" }
                    if ($common.ContainsKey($key)) { $common[$key]++ } else { $common[$key] = 1 }
                }
            }
        }
        if ($common.Count -gt 0) {
            Write-Output ''
            Write-Output ('--- Vanligaste extra-rader utanför interface (antal enheter av ' + $AllFindings.Count + ') ' + ('-' * 8))
            $top = $common.GetEnumerator() | Sort-Object @{ Expression = { $_.Value }; Descending = $true }, @{ Expression = { $_.Key } } | Select-Object -First 25
            foreach ($t in $top) { Write-Output ('  {0,3}  {1}' -f $t.Value, $t.Key) }
            if ($common.Count -gt 25) { Write-Output ('  ... och {0} till (se CSV)' -f ($common.Count - 25)) }
            Write-Output '  Rader som finns på (nästan) alla enheter: lägg i golden (required) om de ska finnas, annars i extra_ignore.'
        }
    }
}

function Get-Negation([string]$Line) {
    if ($Line.StartsWith('no ')) { return $Line.Substring(3) }
    return "no $Line"
}

function Test-Replaces([string]$Missing, [string]$Other) {
    # Ersätter tillägget av $Missing raden $Other (så att inget 'no' behövs)?
    if ($Other.StartsWith('re:')) { return $false }
    if ($Missing.StartsWith('re:')) {
        # regex-krav (t.ex. 'ip address 10.70.0.x ...'): samma kommando med annat värde ersätts av kravet.
        # Jämför den fasta inledningen (minst två ord, t.ex. "ip address ") med den avvikande raden.
        $lit = [regex]::Match($Missing.Substring(3).TrimStart('^'), '^[A-Za-z0-9 _:/,-]+').Value
        $cut = $lit.LastIndexOf(' ')
        if ($cut -gt 0) {
            $prefix = $lit.Substring(0, $cut + 1)
            if ($prefix.Trim().Contains(' ') -and $Other.StartsWith($prefix)) { return $true }
        }
        return $false
    }
    if ($Missing -eq "no $Other") { return $true }
    $m = @($Missing -split ' ')
    $o = @($Other -split ' ')
    # $Other är en utökning av $Missing: "transport input ssh" ersätter "transport input ssh telnet"
    if ($m.Count -ge 2 -and $o.Count -gt $m.Count) {
        $same = $true
        for ($i = 0; $i -lt $m.Count; $i++) { if ($m[$i] -ne $o[$i]) { $same = $false; break } }
        if ($same) { return $true }
    }
    # samma kommando, annat värde: "switchport access vlan 20" ersätter "... vlan 10"
    if ($m.Count -ge 3 -and $m.Count -eq $o.Count) {
        $same = $true
        for ($i = 0; $i -lt ($m.Count - 1); $i++) { if ($m[$i] -ne $o[$i]) { $same = $false; break } }
        if ($same) { return $true }
    }
    return $false
}

function New-ActionRows($AllFindings, $Errors, $Meta) {
    # En rad per avvikelse med föreslagen åtgärd. Inget körs automatiskt.
    # ordning: 1 = ta bort (gör först), 2 = lägg till, 0 = ingen kommandorad (info/manuellt)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($dev in $AllFindings.Keys) {
        $fs = $AllFindings[$dev].ToArray()
        $m = $Meta[$dev]
        foreach ($f in $fs) {
            $action = ''; $cmd = ''; $order = 0
            $repl = $null
            # regex-krav visas läsbart i CSV:n (skärmrapporten visar råa mönstret som förut)
            $lineOut = $f.line
            if ($f.kind -eq 'MISSING' -and $f.line.StartsWith('re:')) { $lineOut = 'Saknar rad som matchar: ' + $f.line.Substring(3) }
            if ($f.kind -eq 'EXTRA' -or $f.kind -eq 'FORBIDDEN') {
                foreach ($mf in ($fs | Where-Object { $_.kind -eq 'MISSING' -and $_.scope -eq $f.scope })) {
                    if (Test-Replaces $mf.line $f.line) {
                        $repl = $mf.line
                        if ($repl.StartsWith('re:')) { $repl = 'en rad som matchar ' + $repl.Substring(3) }
                        break
                    }
                }
            }
            if ($f.kind -eq 'MISSING') {
                if ($f.line.StartsWith('re:')) {
                    $action = 'Lägg till rad som matchar mönstret (fyll i värde manuellt)'
                }
                else { $action = 'Lägg till'; $cmd = $f.line; $order = 2 }
            }
            elseif ($f.kind -eq 'FORBIDDEN') {
                if ($null -ne $repl) { $action = "Åtgärdas av att raden '$repl' läggs till/ändras (inget separat ta bort-kommando behövs)" }
                else { $action = 'Ta bort (förbjuden rad)'; $cmd = Get-Negation $f.line; $order = 1 }
            }
            elseif ($f.kind -eq 'EXTRA') {
                if ($null -ne $repl) { $action = "Åtgärdas av att raden '$repl' läggs till/ändras (inget separat ta bort-kommando behövs)" }
                else { $action = 'Granska: ta bort om avvikelsen inte är avsiktlig'; $cmd = Get-Negation $f.line; $order = 1 }
            }
            elseif ($f.kind -eq 'NO_PROFILE') {
                $action = 'Lägg till regel i interface_rules för porten (eller profil IGNORE)'
            }
            $rows.Add([pscustomobject]@{
                device = $f.device; host = $m['host']; group = $m['group']; template = $m['template']
                context = $f.context; scope = $f.scope; profile = $f.profile; kind = $f.kind
                severity = $f.severity; line = $lineOut; action = $action; command = $cmd; ordning = $order
            })
        }
    }
    foreach ($dev in $Errors.Keys) {
        $m = $Meta[$dev]
        $h = ''; $g = ''; $t = ''
        if ($null -ne $m) { $h = $m['host']; $g = $m['group']; $t = $m['template'] }
        $rows.Add([pscustomobject]@{
            device = $dev; host = $h; group = $g; template = $t
            context = ''; scope = ''; profile = ''; kind = 'FEL'
            severity = 'hög'; line = [string]$Errors[$dev]
            action = 'Enheten kunde inte kontrolleras: åtgärda anslutning/behörighet/inventory och kör om'
            command = ''; ordning = 0
        })
    }
    return , $rows
}

# --------------------------------------------------------------------------
# .xlsx-export (ingen modul, bara inbyggda .NET-klasser: zip + rå OOXML-xml).
# En enda flik, kolumnbredd beräknad från innehållets längd (ungefärlig "autofit").
# --------------------------------------------------------------------------
function Escape-XmlText([string]$s) {
    if ($null -eq $s) { return '' }
    $s = $s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    # Excel/XML tillåter inte styrtecken (utom tab/nl/cr) - rensa bort dem istället för att krascha
    return [regex]::Replace($s, '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
}

function Get-ExcelColLetter([int]$Num) {
    # 1-baserat kolumnnummer -> Excel-bokstav (1=A, 27=AA, ...)
    $s = ''
    $n = $Num
    while ($n -gt 0) {
        $m = ($n - 1) % 26
        $s = [string][char](65 + $m) + $s
        $n = [int][Math]::Floor(($n - 1) / 26)
    }
    return $s
}

function Add-ZipEntryText($Zip, [string]$EntryName, [string]$Content) {
    $entry = $Zip.CreateEntry($EntryName, [System.IO.Compression.CompressionLevel]::Optimal)
    $stream = $entry.Open()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally { $stream.Close() }
}

function New-SimpleXlsx([string]$Path, [string[]]$Cols, $Rows) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue

    $n = $Cols.Count
    $widths = New-Object 'int[]' $n
    for ($i = 0; $i -lt $n; $i++) { $widths[$i] = $Cols[$i].Length }
    foreach ($r in $Rows) {
        for ($i = 0; $i -lt $n; $i++) {
            $v = [string]$r.($Cols[$i])
            if ($v.Length -gt $widths[$i]) { $widths[$i] = $v.Length }
        }
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><cols>')
    for ($i = 0; $i -lt $n; $i++) {
        $w = [Math]::Min(60, [Math]::Max(8, $widths[$i] + 2))
        [void]$sb.Append(('<col min="{0}" max="{0}" width="{1}" customWidth="1"/>' -f ($i + 1), $w))
    }
    [void]$sb.Append('</cols><sheetData><row r="1">')
    for ($i = 0; $i -lt $n; $i++) {
        $cell = Get-ExcelColLetter ($i + 1)
        [void]$sb.Append(('<c r="{0}1" t="inlineStr"><is><t xml:space="preserve">{1}</t></is></c>' -f $cell, (Escape-XmlText $Cols[$i])))
    }
    [void]$sb.Append('</row>')
    $rowNum = 2
    foreach ($r in $Rows) {
        [void]$sb.Append(('<row r="{0}">' -f $rowNum))
        for ($i = 0; $i -lt $n; $i++) {
            $cell = Get-ExcelColLetter ($i + 1)
            $v = [string]$r.($Cols[$i])
            [void]$sb.Append(('<c r="{0}{1}" t="inlineStr"><is><t xml:space="preserve">{2}</t></is></c>' -f $cell, $rowNum, (Escape-XmlText $v)))
        }
        [void]$sb.Append('</row>')
        $rowNum++
    }
    [void]$sb.Append('</sheetData></worksheet>')

    $contentTypesXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
    $relsXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    $workbookXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="goldencheck" sheetId="1" r:id="rId1"/></sheets></workbook>'
    $workbookRelsXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'

    $fullPath = Resolve-FullPath $Path
    if (Test-Path -LiteralPath $fullPath) { Remove-Item -LiteralPath $fullPath -Force }
    $zip = [System.IO.Compression.ZipFile]::Open($fullPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        Add-ZipEntryText $zip '[Content_Types].xml' $contentTypesXml
        Add-ZipEntryText $zip '_rels/.rels' $relsXml
        Add-ZipEntryText $zip 'xl/workbook.xml' $workbookXml
        Add-ZipEntryText $zip 'xl/_rels/workbook.xml.rels' $workbookRelsXml
        Add-ZipEntryText $zip 'xl/worksheets/sheet1.xml' $sb.ToString()
    }
    finally { $zip.Dispose() }
}

function Write-Reports($AllFindings, $Errors, $Meta, [string]$JsonPath, [string]$CsvPath, [bool]$Full, [bool]$WriteXlsx = $false) {
    $rows = New-ActionRows $AllFindings $Errors $Meta
    if ($Full) {
        $cols = 'device', 'host', 'group', 'template', 'context', 'scope', 'profile', 'kind', 'severity', 'line', 'action', 'command', 'ordning'
    }
    else {
        # Standard: avvikande konfiguration + enheter som inte kunde skannas (FEL). En enhet som saknas i
        # CSV:n ska aldrig kunna misstas för en ren enhet. Portar utan profil visas bara på skärmen.
        $keep = New-Object 'System.Collections.Generic.List[object]'
        foreach ($r in $rows) {
            if ($r.kind -eq 'MISSING' -or $r.kind -eq 'EXTRA' -or $r.kind -eq 'FORBIDDEN' -or $r.kind -eq 'FEL') { $keep.Add($r) }
        }
        $rows = $keep
        $cols = 'device', 'host', 'group', 'template', 'profile', 'scope', 'kind', 'severity', 'line'
    }
    if ($JsonPath) {
        $j = ConvertTo-Json -InputObject @($rows.ToArray()) -Depth 3
        [System.IO.File]::WriteAllText((Resolve-FullPath $JsonPath), $j, (New-Object System.Text.UTF8Encoding($false)))
    }
    if ($CsvPath) {
        # UTF-8 med BOM så att Excel läser å/ä/ö rätt; semikolon som avgränsare
        if ($rows.Count -gt 0) {
            $lines = @($rows.ToArray() | Select-Object $cols | ConvertTo-Csv -Delimiter ';' -NoTypeInformation)
        }
        else { $lines = @(($cols | ForEach-Object { '"' + $_ + '"' }) -join ';') }
        $csvFile = Resolve-FullPath $CsvPath
        [System.IO.File]::WriteAllText($csvFile, (($lines -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($true)))
        if ($WriteXlsx) {
            $xlsxFile = [System.IO.Path]::ChangeExtension($csvFile, '.xlsx')
            try { New-SimpleXlsx $xlsxFile $cols @($rows.ToArray()) }
            catch {
                [Console]::Error.WriteLine("Kunde inte skriva .xlsx ($xlsxFile): $($_.Exception.Message)")
                $xlsxFile = $null
            }
            return $xlsxFile
        }
    }
    return $null
}

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
function Repair-PsdKeys([string]$Text) {
    # Nycklar med bindestreck (CA03-01, access-user) måste stå inom citationstecken i .psd1.
    # Lägg till dem automatiskt. Rör inte kommentarer eller text inom citationstecken.
    $rx = "(^|[;{])(\s*)([A-Za-z0-9_.]+(?:-[A-Za-z0-9_.]+)+)(\s*=)(?!=)"
    $out = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in ($Text -split "\r?\n")) {
        if ($line.TrimStart().StartsWith('#')) { $out.Add($line); continue }
        $out.Add([regex]::Replace($line, $rx, [System.Text.RegularExpressions.MatchEvaluator]{
            param($m)
            $before = $line.Substring(0, $m.Index)
            $quotes = ($before.ToCharArray() | Where-Object { $_ -eq [char]39 } | Measure-Object).Count
            if (($quotes % 2) -eq 1 -or $before.Contains('#')) { return $m.Value }   # inuti sträng/kommentar
            return $m.Groups[1].Value + $m.Groups[2].Value + "'" + $m.Groups[3].Value + "'" + $m.Groups[4].Value
        }))
    }
    return ($out -join "`r`n")
}

function Import-DataFile([string]$Path, [string]$What) {
    $full = Resolve-FullPath $Path
    $tmp = $null
    $source = $full
    try {
        $text = [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)
        $fixed = Repair-PsdKeys $text
        $normalized = (($text -split "\r?\n") -join "`r`n")     # jämför utan radslutsskillnader
        if ($fixed -ne $normalized) {
            try {
                $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('goldencheck_' + [guid]::NewGuid().ToString('N') + '.psd1')
                [System.IO.File]::WriteAllText($tmp, $fixed, (New-Object System.Text.UTF8Encoding($true)))
                $source = $tmp
            }
            catch { $tmp = $null; $source = $full }    # temp ej skrivbar: läs originalet som det är
        }
        $data = Import-PowerShellDataFile -Path $source
        if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        return $data
    }
    catch {
        $msg = $_.Exception.Message
        if ($tmp) { $msg = $msg.Replace($tmp, $full) }         # visa användarens fil, inte temp-filen
        # Ge radnummer för vanliga syntaxfel (saknad parentes/citationstecken m.m.)
        $detail = ''
        try {
            $tokens = $null; $perr = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$perr)
            if ($perr -and $perr.Count -gt 0) {
                $e0 = $perr[0]
                $detail = "Rad $($e0.Extent.StartLineNumber): $($e0.Message)"
            }
        } catch { }
        if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        [Console]::Error.WriteLine("Kunde inte läsa $What ($Path): $msg")
        if ($detail) { [Console]::Error.WriteLine("  -> $detail") }
        [Console]::Error.WriteLine("Vanliga orsaker: saknat tecken (@{ } ( ) ' ), citationstecken inuti en sträng som inte dubblats ('' ), " +
                                   "eller uttryck/variabler (bara data tillåts i .psd1).")
        exit 2
    }
}

# --------------------------------------------------------------------------
# Enkelt format 1: golden-mapp med vanliga config.txt-filer (en per "template")
# --------------------------------------------------------------------------
function Build-RegexFromTemplate([string]$Line) {
    # Bygger regex av en rad som innehåller <ANY> (ett godtyckligt ord/värde) och/eller
    # <re:eget uttryck>. Resten av raden escapas (behandlas som vanlig text). Ankras i båda ändar.
    $sb = New-Object System.Text.StringBuilder
    $pos = 0
    foreach ($m in [regex]::Matches($Line, '<ANY>|<re:(.*?)>')) {
        if ($m.Index -gt $pos) { [void]$sb.Append([regex]::Escape($Line.Substring($pos, $m.Index - $pos))) }
        if ($m.Value -eq '<ANY>') { [void]$sb.Append('\S+') }
        else { [void]$sb.Append($m.Groups[1].Value) }
        $pos = $m.Index + $m.Length
    }
    if ($pos -lt $Line.Length) { [void]$sb.Append([regex]::Escape($Line.Substring($pos))) }
    return ('^' + $sb.ToString() + '$')
}

function ConvertTo-GoldenRequiredLine([string]$Line) {
    # Rad som måste finnas. 're:<uttryck>' = eget regex (samma konvention som profiles.psd1).
    # <ANY>/<re:...> i raden = bygg regex automatiskt. Annars: exakt text.
    if ($Line.StartsWith('re:')) { return $Line }
    if ($Line -match '<ANY>' -or $Line -match '<re:') { return 're:' + (Build-RegexFromTemplate $Line) }
    return $Line
}

function ConvertTo-GoldenForbiddenPattern([string]$Line) {
    # Mönster för en rad som INTE får finnas. 're:<uttryck>' = eget regex, ej ankrat (full kontroll).
    # <ANY>/<re:...> = bygg regex automatiskt (ankrat). Annars: exakt text (ankrat).
    if ($Line.StartsWith('re:')) { return $Line.Substring(3) }
    if ($Line -match '<ANY>' -or $Line -match '<re:') { return (Build-RegexFromTemplate $Line) }
    return ('^' + [regex]::Escape($Line) + '$')
}

function Import-ConfigTxtProfile([string]$Path) {
    # Läser en "golden"-fil skriven i vanlig IOS-syntax (indrag = tillhör raden ovanför, precis
    # som en running-config) och bygger samma struktur som profiles.psd1 använder internt.
    #   ~ framför en rad   -> förbjuden rad (istället för krävd)
    #   ? framför en rad   -> raden krävs inte, men flaggas heller ALDRIG som extra/avvikande om den
    #                         finns (skiljer sig från att bara utelämna raden, vilket bara spelar roll
    #                         när "# extra: on" är satt - annars är allt som inte står i filen redan tyst)
    #   <ANY>              -> ett godtyckligt ord/värde (t.ex. hostname, IP, tid)
    #   <re:eget uttryck>  -> eget regex när <ANY> inte räcker
    #   re:eget uttryck    -> hela raden är ett eget regex (samma konvention som profiles.psd1)
    #   # extra: on              -> flagga rader på enheten som inte finns i golden alls (se README)
    #   # extra_ignore: ..       -> undanta ett mönster från extra-kontrollen (kan upprepas)
    #   # port_check: off        -> hoppa över portkontroll helt för denna template (ingen NO_PROFILE,
    #                              inga interface_rules krävs). Används tills portprofiler finns i enkel form.
    #   # kommentar              -> ignoreras
    $raw = [System.IO.File]::ReadAllText((Resolve-FullPath $Path), [System.Text.Encoding]::UTF8)
    $extraOn = $false
    $portCheck = $null
    $extraIgnore = New-Object 'System.Collections.Generic.List[string]'
    $body = New-Object 'System.Collections.Generic.List[string]'
    foreach ($raw0 in ($raw -split "\r?\n")) {
        $t = $raw0.Trim()
        if ($t.StartsWith('#')) {
            if ($t -match '^#\s*extra\s*:\s*(on|av|off|true|false)\s*$') { $extraOn = ($Matches[1] -in @('on', 'true')) }
            elseif ($t -match '^#\s*extra_ignore\s*:\s*(.+)$') { $extraIgnore.Add($Matches[1].Trim()) }
            elseif ($t -match '^#\s*port_check\s*:\s*(on|av|off|true|false)\s*$') { $portCheck = ($Matches[1] -in @('on', 'true')) }
            continue
        }
        $body.Add($raw0)
    }
    $parse = ConvertFrom-IosConfig ($body -join "`r`n")

    $required = New-Object 'System.Collections.Generic.List[string]'
    $forbidden = New-Object 'System.Collections.Generic.List[string]'
    $blocks = New-Object 'System.Collections.Generic.List[object]'

    foreach ($obj in $parse) {
        $text = Norm $obj.Text
        $isForbid = $text.StartsWith('~')
        $isIgnore = $text.StartsWith('?')
        if ($isForbid -or $isIgnore) { $text = Norm $text.Substring(1) }

        if ($obj.Children.Count -eq 0) {
            if ($isIgnore) { $extraIgnore.Add((ConvertTo-GoldenForbiddenPattern $text)) }
            elseif ($isForbid) { $forbidden.Add((ConvertTo-GoldenForbiddenPattern $text)) }
            else { $required.Add((ConvertTo-GoldenRequiredLine $text)) }
            continue
        }

        $parentPat = (ConvertTo-GoldenForbiddenPattern $text)   # samma logik ger ett ankrat/obyggt mönster
        if ($isIgnore) {
            # ?-prefix på en rad med indragna barn = ignorera hela avsnittet (varken krav eller kontroll
            # av barnen), och visa det aldrig som en extra toppnivårad.
            $extraIgnore.Add($parentPat)
            continue
        }

        # Block (t.ex. "aaa group server ..." eller "line vty 0 4" med indragna rader under sig).
        # Föräldraraden läggs även till i 'required' (som eget regex) så att HELA blocket flaggas
        # som saknat (MISSING) om det inte finns alls - annars kollas bara barnen när blocket finns.
        if (-not $isForbid) { $required.Add('re:' + $parentPat) }
        $breq = New-Object 'System.Collections.Generic.List[string]'
        $bforb = New-Object 'System.Collections.Generic.List[string]'
        $bign = New-Object 'System.Collections.Generic.List[string]'
        foreach ($childRaw in $obj.Children) {
            $c = Norm $childRaw
            if ($c.StartsWith('?')) { $bign.Add((ConvertTo-GoldenForbiddenPattern (Norm $c.Substring(1)))) }
            elseif ($c.StartsWith('~')) { $bforb.Add((ConvertTo-GoldenForbiddenPattern (Norm $c.Substring(1)))) }
            else { $breq.Add((ConvertTo-GoldenRequiredLine $c)) }
        }
        $blocks.Add(@{ parent = $parentPat; required = $breq.ToArray(); forbidden = $bforb.ToArray(); ignore = $bign.ToArray() })
    }

    $gp = @{ required = $required.ToArray(); forbidden = $forbidden.ToArray(); blocks = $blocks.ToArray() }
    if ($extraOn) {
        $gp['extra'] = $true
        if ($extraIgnore.Count -gt 0) { $gp['extra_ignore'] = $extraIgnore.ToArray() }
    }
    # '_port_check' är inget profiles.psd1-nyckelnamn - plockas ut av anroparen och sätts som
    # 'report_unmatched' på TEMPLATEN (inte på den globala profilen) innan den används.
    if ($null -ne $portCheck) { $gp['_port_check'] = $portCheck }
    return $gp
}

# --------------------------------------------------------------------------
# Enkelt format 2: switches.csv istället för devices i inventory.psd1
# --------------------------------------------------------------------------
function Import-SwitchesCsv([string]$Path) {
    # Kolumner (rubrikrad krävs): name;host;group;template  (transport/key/port är valfria extra).
    # Avgränsare gissas från rubrikraden (; eller ,). 'template' avgör vilken golden-fil (eller
    # vilken template i inventory.psd1) switchen ska jämföras mot.
    $full = Resolve-FullPath $Path
    $raw = [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)
    $firstLine = (($raw -split "\r?\n") | Where-Object { $_.Trim() -ne '' } | Select-Object -First 1)
    $delim = ','
    if ($firstLine -and (@($firstLine.Split(';'))).Count -gt (@($firstLine.Split(','))).Count) { $delim = ';' }
    try { $rows = @($raw | ConvertFrom-Csv -Delimiter $delim) }
    catch {
        [Console]::Error.WriteLine("Kunde inte läsa switches-filen (${Path}): $($_.Exception.Message)")
        exit 2
    }
    # Vanlig hashtable (inte [ordered]) - resten av skriptet anropar $devices.ContainsKey(...)
    # som en vanlig Hashtable har men en OrderedDictionary saknar. Ordningen spelar ingen roll
    # eftersom enhetslistan ändå sorteras om (Sort-Ordinal) innan den används.
    $devs = @{}
    foreach ($r in $rows) {
        $name = ''
        if ($r.PSObject.Properties.Match('name').Count -gt 0) { $name = ([string]$r.name).Trim() }
        if (-not $name) { continue }
        $e = @{}
        foreach ($col in @('host', 'group', 'template', 'transport', 'key', 'port', 'plink_path', 'hostkey')) {
            # (samma kolumner som devices stöder i inventory.psd1)
            if ($r.PSObject.Properties.Match($col).Count -gt 0) {
                $v = ([string]$r.$col).Trim()
                if ($v) { $e[$col] = $v }
            }
        }
        if (-not $e.ContainsKey('host')) {
            [Console]::Error.WriteLine("Switches-filen ($Path): raden '$name' saknar kolumnen 'host'.")
            exit 2
        }
        $devs[$name] = $e
    }
    if ($devs.Count -eq 0) {
        [Console]::Error.WriteLine("Hittade inga enheter i $Path. Kontrollera rubrikraden (name;host;group;template).")
        exit 2
    }
    return $devs
}

# --------------------------------------------------------------------------
# Läs in profiler och enheter - enkelt format om det finns, annars .psd1 (avancerat)
# --------------------------------------------------------------------------
$profData = @{}
if ($ProfilesExplicit -or (Test-Path -LiteralPath $Profiles -PathType Leaf)) { $profData = Import-DataFile $Profiles 'profiles' }
if ($null -eq $profData) { $profData = @{} }
if (-not $profData.ContainsKey('global') -or $null -eq $profData['global']) { $profData['global'] = @{} }
if (-not $profData.ContainsKey('common_ignore') -or $null -eq $profData['common_ignore']) { $profData['common_ignore'] = @() }
if (-not $profData.ContainsKey('interface_profiles') -or $null -eq $profData['interface_profiles']) { $profData['interface_profiles'] = @{} }

$invData = @{}
if ($InventoryExplicit -or (Test-Path -LiteralPath $Inventory -PathType Leaf)) { $invData = Import-DataFile $Inventory 'inventory' }
if ($null -eq $invData) { $invData = @{} }

$defaults = @{}
if ($invData.ContainsKey('defaults') -and $null -ne $invData['defaults']) { $defaults = $invData['defaults'] }
$templates = @{}
if ($invData.ContainsKey('templates') -and $null -ne $invData['templates']) { $templates = $invData['templates'] }
$groups = @{}
if ($invData.ContainsKey('groups') -and $null -ne $invData['groups']) { $groups = $invData['groups'] }

# golden\*.txt: en fil per template. Skriver in/över profData['global'][namn] och registrerar
# (eller kompletterar) en template med samma namn, så att resten av skriptet inte behöver bry sig
# om varifrån den globala profilen kom.
if ($GoldenDirExplicit -and -not (Test-Path -LiteralPath $GoldenDir -PathType Container)) {
    [Console]::Error.WriteLine("Hittar inte golden-mappen: $GoldenDir")
    exit 2
}
if (Test-Path -LiteralPath $GoldenDir -PathType Container) {
    foreach ($f in (Get-ChildItem -LiteralPath $GoldenDir -Filter '*.txt' -File | Sort-Object Name)) {
        $tname = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
        try { $gp = Import-ConfigTxtProfile $f.FullName }
        catch {
            [Console]::Error.WriteLine("Kunde inte läsa golden-filen $($f.FullName): $($_.Exception.Message)")
            exit 2
        }
        $portCheck = $null
        if ($gp.ContainsKey('_port_check')) { $portCheck = $gp['_port_check']; $gp.Remove('_port_check') }
        $profData['global'][$tname] = $gp
        if ($templates.ContainsKey($tname) -and $null -ne $templates[$tname]) {
            $t = @{}
            foreach ($k in $templates[$tname].Keys) { $t[$k] = $templates[$tname][$k] }
            $t['global'] = $tname
            $templates[$tname] = $t
        }
        else { $templates[$tname] = @{ global = $tname } }
        if ($null -ne $portCheck) { $templates[$tname]['report_unmatched'] = $portCheck }
    }
}

# switches.csv: ersätter devices-listan från inventory.psd1 helt och hållet när filen finns.
if ($SwitchesExplicit -and -not (Test-Path -LiteralPath $Switches -PathType Leaf)) {
    [Console]::Error.WriteLine("Hittar inte switches-filen: $Switches")
    exit 2
}
if (Test-Path -LiteralPath $Switches -PathType Leaf) { $devices = Import-SwitchesCsv $Switches }
else { $devices = $invData['devices'] }

if ($null -eq $devices -or $devices.Count -eq 0) {
    [Console]::Error.WriteLine("Inga enheter hittades. Lägg dem i $Switches (kolumner: name;host;group;template) " +
                               "eller i $Inventory ('devices = @{ ... }').")
    exit 2
}
$allNames = @((Sort-Ordinal $devices.Keys).ToArray())
$templateNames = @((Sort-Ordinal $templates.Keys).ToArray())

$ProfileKeys = @('global', 'interface_rules', 'report_unmatched', 'vars')

# --------------------------------------------------------------------------
# Templates, grupper och enhetskonfiguration
# --------------------------------------------------------------------------
function Get-TemplateNameFor([hashtable]$Entry) {
    # enhetens egen template, annars gruppens standardtemplate
    if ($Entry.ContainsKey('template') -and $Entry['template']) { return [string]$Entry['template'] }
    if ($Entry.ContainsKey('group') -and $Entry['group'] -and $groups.ContainsKey([string]$Entry['group'])) {
        $gd = $groups[[string]$Entry['group']]
        if ($null -ne $gd -and $gd.ContainsKey('template') -and $gd['template']) { return [string]$gd['template'] }
    }
    return ''
}

function Resolve-DeviceConfig([hashtable]$Entry, [string]$TemplateOverride) {
    # Ordning: defaults < template < enhetens egna värden.
    # Vald template (-Template/menyn) ersätter enhetens egna profilinställningar
    # (global, interface_rules, report_unmatched, vars); host/transport/key m.m. behålls.
    $tName = $TemplateOverride
    if (-not $tName) { $tName = Get-TemplateNameFor $Entry }
    $tmpl = @{}
    if ($tName) {
        if (-not $templates.ContainsKey($tName)) {
            throw "Template '$tName' finns inte i inventory (templates). Tillgängliga: $($templateNames -join ', ')"
        }
        $tmpl = $templates[$tName]
    }
    $own = $Entry
    if ($TemplateOverride) {
        $own = @{}
        foreach ($k in $Entry.Keys) { if ($ProfileKeys -notcontains $k) { $own[$k] = $Entry[$k] } }
    }
    $cfg = Merge-Hash (Merge-Hash $defaults $tmpl) $own
    $vars = @{}
    foreach ($src in @($defaults['vars'], $tmpl['vars'], $own['vars'])) {
        if ($null -ne $src) { foreach ($k in $src.Keys) { $vars[$k] = $src[$k] } }
    }
    $cfg['vars'] = $vars
    $cfg['template'] = $tName
    return $cfg
}

function Get-GroupNames {
    $set = New-Set @()
    foreach ($n in $allNames) {
        if ($devices[$n].ContainsKey('group') -and $devices[$n]['group']) { [void]$set.Add([string]$devices[$n]['group']) }
    }
    foreach ($g in $groups.Keys) { [void]$set.Add([string]$g) }
    return @((Sort-Ordinal $set).ToArray())
}

function Get-DevicesInGroup([string]$GroupName) {
    return @(foreach ($n in $allNames) {
        $dg = ''
        if ($devices[$n].ContainsKey('group') -and $devices[$n]['group']) { $dg = [string]$devices[$n]['group'] }
        if ($dg -eq $GroupName) { $n }
    })
}

function Build-Targets([string[]]$Names, [string]$TemplateOverride) {
    $t = [ordered]@{}
    foreach ($n in $Names) {
        try { $t[$n] = Resolve-DeviceConfig $devices[$n] $TemplateOverride }
        catch { $errors[$n] = $_.Exception.Message }
    }
    return $t
}

function Build-AdHoc([string]$Name, [string]$TemplateName) {
    # en specifik switch: ur inventory (om namnet finns) eller ny IP/hostnamn
    $t = [ordered]@{}
    if ($devices.ContainsKey($Name)) { $entry = $devices[$Name] } else { $entry = @{ host = $Name } }
    try { $t[$Name] = Resolve-DeviceConfig $entry $TemplateName }
    catch { $errors[$Name] = $_.Exception.Message }
    return $t
}

# --------------------------------------------------------------------------
# Startmeny
# --------------------------------------------------------------------------
function Read-Line([string]$Prompt) {
    try { $r = Read-Host $Prompt } catch { return $null }
    if ($null -eq $r) { return $null }
    return $r.Trim()
}

function Invoke-CacheHostKeys($Targets, [string]$User, [string]$Password, [string]$PlinkName, [string]$LogPath, [bool]$AcceptAll = $false) {
    # Går igenom enheterna: visar fingeravtrycket för dem vars värdnyckel inte är cachad och frågar innan den sparas.
    # En enhet som strular (timeout, fel lösenord, nätfel m.m.) ska aldrig stoppa resten av listan.
    $log = New-Object 'System.Collections.Generic.List[string]'
    $log.Add("enhet`thost`tfingeravtryck`tresultat")
    $acceptAll = $AcceptAll
    $i = 0
    $n = $Targets.Count
    $stop = $false
    foreach ($name in @($Targets.Keys)) {
        $i++
        try {
            $dev = $Targets[$name]
            $h = [string]$dev['host']
            if (-not $h) { Write-Host "[$i/$n] ${name}: saknar host i inventory"; continue }
            $pl = $PlinkName
            if ($dev.ContainsKey('plink_path') -and $dev['plink_path']) { $pl = [string]$dev['plink_path'] }
            $exe = Resolve-Exe $pl
            $usesKey = ($dev.ContainsKey('key') -and $dev['key'])
            $base = @('-ssh', '-l', $User)
            if ($dev.ContainsKey('port') -and $dev['port']) { $base += @('-P', [string]$dev['port']) }
            if ($usesKey) { $base += @('-i', [string]$dev['key']) }

            # 1. Finns nyckeln redan? (-batch ger fel med fingeravtryck om den inte är cachad)
            $r = Invoke-External $exe (@('-batch') + $base + @($h, 'exit')) 30
            $txt = ($r.Out + "`n" + $r.Err)
            if ($txt -notmatch '(?i)host key is not cached') {
                if ($txt -match '(?i)network error|timed out|refused|does not exist|unreachable|no route') {
                    $first = ($txt.Trim() -split "\r?\n")[0]
                    Write-Host "[$i/$n] $name  $h  KAN INTE NÅS: $first"
                    $log.Add("$name`t$h`t`tkan inte nås: $first")
                }
                else {
                    Write-Host "[$i/$n] $name  $h  redan cachad"
                    $log.Add("$name`t$h`t`tredan cachad")
                }
                continue
            }

            # 2. Visa fingeravtrycket och fråga (om inte -AcceptAllHostKeys/tidigare 'a' redan svarat ja för alla)
            $fp = [regex]::Match($txt, '(?m)^\s+((?:ssh|ecdsa)[\w-]*\s+\d+\s+(?:SHA256:\S+|(?:[0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2}))\s*$').Groups[1].Value
            if (-not $fp) { $fp = '(kunde inte läsa fingeravtrycket)' }
            Write-Host ''
            Write-Host "[$i/$n] $name  $h"
            Write-Host "        nyckel: $fp"
            $ok = $acceptAll
            if (-not $ok) {
                $ans = Read-Line 'Lita på och cacha nyckeln? (j = ja, n = nej, a = ja för alla återstående, q = avbryt)'
                if ($ans -eq 'q' -or -not $ans) { $stop = $true }
                elseif ($ans -eq 'j' -or $ans -eq 'a') { $ok = $true; if ($ans -eq 'a') { $acceptAll = $true } }
            }
            if ($stop) { $log.Add("$name`t$h`t$fp`tavbröts"); break }
            if (-not $ok) {
                Write-Host '        hoppades över'
                $log.Add("$name`t$h`t$fp`thoppades över")
                continue
            }

            # 3. Cacha (svara "y" på plinks värdnyckelfråga). Om enheten kräver lösenord (ingen 'key' i
            # inventory) skickas det med direkt efteråt, annars hänger plink kvar på lösenordsprompten
            # tills timeout - det var orsaken till att en enhet utan nyckel kunde stoppa hela resten.
            $acceptInput = "y`n"
            if (-not $usesKey -and $Password) { $acceptInput = "y`n$Password`n" }
            [void](Invoke-External $exe (@() + $base + @($h, 'exit')) 30 $acceptInput)
            $v = Invoke-External $exe (@('-batch') + $base + @($h, 'exit')) 30
            if (($v.Out + "`n" + $v.Err) -match '(?i)host key is not cached') {
                Write-Host '        MISSLYCKADES: nyckeln cachades inte'
                $log.Add("$name`t$h`t$fp`tmisslyckades")
            }
            else {
                Write-Host '        cachad'
                $log.Add("$name`t$h`t$fp`tcachad")
            }
        }
        catch {
            Write-Host "[$i/$n] $name  FEL: $($_.Exception.Message)"
            $log.Add("$name`t`t`tfel: $($_.Exception.Message)")
        }
    }
    try { [System.IO.File]::WriteAllText($LogPath, (($log -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($true))) } catch { $LogPath = $null }
    Write-Host ''
    if ($LogPath) { Write-Host "Logg med fingeravtryck: $LogPath" }
    Write-Host 'Kör nu skanningen igen (t.ex. .\run.cmd -Group access).'
}

function Select-Template([string]$DefaultName) {
    if ($templateNames.Count -eq 0) {
        Write-Host "Inga templates finns i inventory (templates = @{ ... })."
        return $null
    }
    Write-Host ''
    Write-Host 'Templates att jämföra mot:'
    $defIdx = 0
    for ($i = 0; $i -lt $templateNames.Count; $i++) {
        $tn = $templateNames[$i]
        $desc = ''
        $td = $templates[$tn]
        if ($null -ne $td -and $td.ContainsKey('description') -and $td['description']) { $desc = "  - $($td['description'])" }
        $mark = ''
        if ($tn -eq $DefaultName) { $defIdx = $i + 1; $mark = '  [enhetens standard]' }
        Write-Host ('  {0}) {1}{2}{3}' -f ($i + 1), $tn, $desc, $mark)
    }
    $prompt = 'Välj template'
    if ($defIdx -gt 0) { $prompt = "$prompt [$defIdx]" }
    $ans = Read-Line $prompt
    if (-not $ans) { if ($defIdx -gt 0) { return $templateNames[$defIdx - 1] } else { return $null } }
    if ($templates.ContainsKey($ans)) { return $ans }
    $n = 0
    if (-not [int]::TryParse($ans, [ref]$n) -or $n -lt 1 -or $n -gt $templateNames.Count) {
        Write-Host "Ogiltigt val: $ans"
        return $null
    }
    return $templateNames[$n - 1]
}

function Invoke-GroupMenu {
    $entries = New-Object 'System.Collections.Generic.List[object]'
    foreach ($g in (Get-GroupNames)) {
        $desc = ''
        if ($groups.ContainsKey($g) -and $null -ne $groups[$g] -and $groups[$g].ContainsKey('description') -and $groups[$g]['description']) {
            $desc = "  - $($groups[$g]['description'])"
        }
        $entries.Add([pscustomobject]@{ Label = $g; Names = @(Get-DevicesInGroup $g); Desc = $desc })
    }
    $ungrouped = @(Get-DevicesInGroup '')
    if ($ungrouped.Count -gt 0) {
        $entries.Add([pscustomobject]@{ Label = '(ingen grupp)'; Names = $ungrouped; Desc = '' })
    }
    Write-Host ''
    Write-Host 'Grupper i hostlistan:'
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $e = $entries[$i]
        Write-Host ('  {0}) {1} ({2} st){3}' -f ($i + 1), $e.Label, $e.Names.Count, $e.Desc)
    }
    Write-Host ('  A) Alla enheter ({0})' -f $allNames.Count)
    $ans = Read-Line 'Välj (t.ex. 1  eller  1,2  eller  A)'
    if (-not $ans) { return $null }
    if ($ans -match '^[aA]$') { return , $allNames }
    $chosen = New-Set @()
    foreach ($tok in @($ans -split '[,\s]+' | Where-Object { $_ })) {
        $n = 0
        if (-not [int]::TryParse($tok, [ref]$n) -or $n -lt 1 -or $n -gt $entries.Count) {
            Write-Host "Ogiltigt val: $tok"
            return $null
        }
        foreach ($nm in $entries[$n - 1].Names) { [void]$chosen.Add($nm) }
    }
    return , @((Sort-Ordinal $chosen).ToArray())
}

function Invoke-MainMenu {
    Write-Host ''
    Write-Host 'goldencheck - vad vill du göra?'
    Write-Host '  1) Scanna hostlista (välj grupp, t.ex. access / DC)'
    Write-Host '  2) Scanna en specifik switch (välj template att jämföra mot)'
    Write-Host '  3) Cacha värdnycklar för en grupp (plink, godkänner alla automatiskt)'
    Write-Host '  Q) Avsluta'
    $ans = Read-Line 'Val'
    if ($ans -eq '1') {
        $names = Invoke-GroupMenu
        if ($null -eq $names) { return $null }
        return (Build-Targets $names '')
    }
    if ($ans -eq '2') {
        $in = Read-Line 'Ange switch (enhetsnamn ur inventory, eller IP/hostnamn)'
        if (-not $in) { return $null }
        $defT = ''
        if ($devices.ContainsKey($in)) { $defT = Get-TemplateNameFor $devices[$in] }
        $tName = Select-Template $defT
        if (-not $tName) { return $null }
        return (Build-AdHoc $in $tName)
    }
    if ($ans -eq '3') {
        $names = Invoke-GroupMenu
        if ($null -eq $names) { return $null }
        # samma som -CacheHostKeys -AcceptAllHostKeys från kommandoraden, men för gruppen vald här
        $script:CacheHostKeys = $true
        $script:AcceptAllHostKeys = $true
        return (Build-Targets $names '')
    }
    return $null
}

# --------------------------------------------------------------------------
# Urval av enheter
# --------------------------------------------------------------------------
function Get-TransportFor([hashtable]$Dev) {
    if ($Transport) { return $Transport }
    if ($Dev.ContainsKey('transport') -and $Dev['transport']) { return [string]$Dev['transport'] }
    return 'plink'
}

$results = [ordered]@{}
$errors = [ordered]@{}

$modes = 0
if ($Target) { $modes++ }
if ($Group) { $modes++ }
if ($Device) { $modes++ }
if ($All) { $modes++ }
if ($modes -gt 1) {
    [Console]::Error.WriteLine('Ange bara en av -Target, -Group, -Device och -All.')
    exit 2
}
if ($Template -and -not $templates.ContainsKey($Template)) {
    [Console]::Error.WriteLine("Okänd template '$Template'. Tillgängliga: $($templateNames -join ', ')")
    exit 2
}

$menuUsed = $false
$targets = $null
if ($Target) {
    $tn = $Template
    if (-not $tn) {
        $defT = ''
        if ($devices.ContainsKey($Target)) { $defT = Get-TemplateNameFor $devices[$Target] }
        $menuUsed = $true
        $tn = Select-Template $defT
    }
    if ($tn) { $targets = Build-AdHoc $Target $tn }
}
elseif ($Group) {
    $known = Get-GroupNames
    $bad = @($Group | Where-Object { $known -notcontains $_ })
    if ($bad.Count -gt 0) {
        [Console]::Error.WriteLine("Okända grupper: $($bad -join ', '). Finns: $($known -join ', ')")
        exit 2
    }
    $sel = New-Set @()
    foreach ($g in $Group) { foreach ($n in (Get-DevicesInGroup $g)) { [void]$sel.Add($n) } }
    $targets = Build-Targets @((Sort-Ordinal $sel).ToArray()) $Template
}
elseif ($Device) {
    $unknown = @($Device | Where-Object { -not $devices.ContainsKey($_) })
    if ($unknown.Count -gt 0) {
        [Console]::Error.WriteLine("Okända enheter: $(($unknown | Sort-Object) -join ', ')")
        exit 2
    }
    $targets = Build-Targets @($allNames | Where-Object { $Device -contains $_ }) $Template
}
elseif ($All) {
    $targets = Build-Targets $allNames $Template
}
else {
    $menuUsed = $true
    $targets = Invoke-MainMenu
}

if ($null -eq $targets -or ($targets.Count -eq 0 -and $errors.Count -eq 0)) {
    [Console]::Error.WriteLine('Inget val gjordes, avbryter. (Utan meny: använd -Group, -Device, -Target eller -All.)')
    exit 2
}
if ($menuUsed -and $targets.Count -gt 0) {
    Write-Host ''
    Write-Host ("Scannar {0} enhet(er): {1}" -f $targets.Count, (@($targets.Keys) -join ', '))
}

# --------------------------------------------------------------------------
# Cacha värdnycklar (plink) - ingen konfig hämtas
# --------------------------------------------------------------------------
if ($CacheHostKeys) {
    if ($Offline) { [Console]::Error.WriteLine('-CacheHostKeys kan inte kombineras med -Offline.'); exit 2 }
    $notPlink = @($targets.Keys | Where-Object { (Get-TransportFor $targets[$_]) -ne 'plink' })
    if ($notPlink.Count -gt 0) {
        [Console]::Error.WriteLine("-CacheHostKeys gäller plink. Dessa enheter använder ssh: $($notPlink -join ', ')")
        exit 2
    }
    $hkUser = $env:NET_USER
    if (-not $hkUser) { $hkUser = Read-Host 'SSH-användare' }
    # Lösenord behövs bara för enheter utan nyckelinloggning - annars hänger plink på lösenordsprompten
    # efter att värdnyckeln godkänts och timar ut (det var buggen som stoppade hela resten av listan).
    $hkPassword = $null
    $hkNeedPw = @($targets.Keys | Where-Object { -not ($targets[$_].ContainsKey('key') -and $targets[$_]['key']) }).Count -gt 0
    if ($hkNeedPw) {
        $hkPassword = $env:NET_PASS
        if (-not $hkPassword) {
            $hkSec = Read-Host 'SSH-lösenord' -AsSecureString
            $hkBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($hkSec)
            try { $hkPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($hkBstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($hkBstr) }
        }
    }
    $hkDir = Join-Path $ScriptDir 'reports'
    if (-not (Test-Path -LiteralPath $hkDir)) { [void](New-Item -ItemType Directory -Path $hkDir) }
    $hkLog = Join-Path $hkDir ('hostkeys_{0}.txt' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Invoke-CacheHostKeys $targets $hkUser $hkPassword $Plink $hkLog ([bool]$AcceptAllHostKeys)
    exit 0
}

# --------------------------------------------------------------------------
# Inloggningsuppgifter (live)
# --------------------------------------------------------------------------
$user = $null
$password = $null
if ($Offline) {
    $Offline = Resolve-FullPath $Offline
}
elseif ($targets.Count -gt 0) {
    $user = $env:NET_USER
    if (-not $user) { $user = Read-Host 'SSH-användare' }

    $needPw = $false
    foreach ($n in $targets.Keys) {
        $d = $targets[$n]
        if ((Get-TransportFor $d) -eq 'plink' -and -not ($d.ContainsKey('key') -and $d['key'])) { $needPw = $true }
    }
    if ($needPw) {
        $password = $env:NET_PASS
        if (-not $password) {
            $sec = Read-Host 'SSH-lösenord' -AsSecureString
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
            try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
    }
}

# --------------------------------------------------------------------------
# Skanna
# --------------------------------------------------------------------------
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportDir = Join-Path $ScriptDir 'reports'
$cfgDir = $null
if ($SaveConfigs) {
    $cfgDir = Join-Path $reportDir "configs_$stamp"
    [void](New-Item -ItemType Directory -Path $cfgDir -Force)
    Write-Host "OBS: hämtade konfigurationer sparas i $cfgDir (innehåller hashar/nycklar - hantera som känsligt)."
}
$meta = [ordered]@{}
$scanInfo = [ordered]@{}
$i = 0
$total = $targets.Count
foreach ($name in @($targets.Keys)) {
    $i++
    $dev = $targets[$name]
    $meta[$name] = @{ host = [string]$dev['host']; group = [string]$dev['group']; template = [string]$dev['template'] }
    try {
        if ($Offline) { $cfg = Get-ConfigOffline $name $Offline }
        else {
            if (-not $dev['host']) { throw "Enheten saknar 'host' i inventory" }
            Write-Host "[$i/$total] $name ($($dev['host']))"
            $t = Get-TransportFor $dev
            if ($t -eq 'ssh') { $cfg = Get-ConfigSsh $dev $user }
            else {
                $pl = $Plink
                if ($dev.ContainsKey('plink_path') -and $dev['plink_path']) { $pl = [string]$dev['plink_path'] }
                $cfg = Get-ConfigPlink $dev $user $password $pl
            }
        }
        $scanInfo[$name] = @($cfg -split "\r?\n").Count
        if ($cfgDir) { [System.IO.File]::WriteAllText((Join-Path $cfgDir "$name.cfg"), $cfg, (New-Object System.Text.UTF8Encoding($false))) }
        $results[$name] = Test-Device $name $dev $cfg $profData
    }
    catch {
        # en trasig enhet ska inte stoppa resten
        $errors[$name] = $_.Exception.Message
    }
}

$reportLines = @(Write-Report $results $errors $meta $scanInfo)
foreach ($l in $reportLines) { Write-Output $l }

# Åtgärdsfil (CSV): skrivs automatiskt om inte -NoCsv
$csvPath = $Csv
if (-not $csvPath -and -not $NoCsv -and ($results.Count -gt 0 -or $errors.Count -gt 0)) {
    if (-not (Test-Path -LiteralPath $reportDir)) { [void](New-Item -ItemType Directory -Path $reportDir) }
    $csvPath = Join-Path $reportDir ("goldencheck_$stamp.csv")
}
$xlsxPath = Write-Reports $results $errors $meta $Json $csvPath ([bool]$WithActions) ([bool]$Xlsx)
if ($csvPath) {
    # hela konsolutskriften sparas bredvid CSV:n (för felsökning/delning)
    $logPath = [System.IO.Path]::ChangeExtension((Resolve-FullPath $csvPath), '.txt')
    try { [System.IO.File]::WriteAllText($logPath, (($reportLines -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($true))) } catch { $logPath = $null }
    Write-Output ''
    Write-Output ('CSV: ' + (Resolve-FullPath $csvPath))
    if ($xlsxPath) { Write-Output ('XLSX: ' + $xlsxPath) }
    if ($logPath) { Write-Output ('Logg: ' + $logPath) }
    if ($errors.Count -gt 0) {
        Write-Output ("OBS: {0} enhet(er) kunde INTE skannas (kolla FEL-raderna): {1}" -f $errors.Count, (@($errors.Keys) -join ', '))
    }
}

$hasFindings = $false
foreach ($k in $results.Keys) { if ($results[$k].Count -gt 0) { $hasFindings = $true } }
if ($hasFindings -or $errors.Count -gt 0) { exit 1 } else { exit 0 }
