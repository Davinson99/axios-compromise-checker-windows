$ErrorActionPreference = 'SilentlyContinue'
$FOUND = $false

function Write-Section($text) {
  Write-Host ""
  Write-Host $text
}

function Flag($msg) {
  Write-Host "  !! $msg"
  $script:FOUND = $true
}

function Ok($msg) {
  Write-Host "  OK: $msg"
}

Write-Host "============================================"
Write-Host "  Axios Supply Chain Attack Detection"
Write-Host "  Windows PowerShell Scanner"
Write-Host "============================================"
Write-Host ""

# 1) Installed axios version via npm list
Write-Host "[1/7] Checking installed axios version..."
if (Get-Command npm -ErrorAction SilentlyContinue) {
  $npmList = npm list axios --depth=10 2>$null | Out-String
  if ($npmList -match 'axios@(1\.14\.1|0\.30\.4)') {
    $matchesFound = [regex]::Matches($npmList, 'axios@(1\.14\.1|0\.30\.4)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
    Flag ("Affected axios version found in node_modules: " + ($matchesFound -join ', '))
  } else {
    Ok "No compromised axios version found via npm list"
  }
} else {
  Write-Host "  SKIP: npm not found"
}

# 2) Lockfiles in current directory
Write-Section "[2/7] Checking lockfiles in current directory..."
if (Test-Path "package-lock.json") {
  $pkgLock = Get-Content "package-lock.json" -Raw
  if ($pkgLock -match '1\.14\.1|0\.30\.4') {
    Flag "Compromised axios version found in package-lock.json"
  } else {
    Ok "package-lock.json clean"
  }
}
if (Test-Path "yarn.lock") {
  $yarnLock = Get-Content "yarn.lock" -Raw
  if ($yarnLock -match '1\.14\.1|0\.30\.4') {
    Flag "Compromised axios version found in yarn.lock"
  } else {
    Ok "yarn.lock clean"
  }
}
if (-not (Test-Path "package-lock.json") -and -not (Test-Path "yarn.lock")) {
  Write-Host "  SKIP: No lockfile found in current directory"
}

# 3) Git history
Write-Section "[3/7] Checking lockfile git history..."
if (Test-Path ".git") {
  if (Get-Command git -ErrorAction SilentlyContinue) {
    $gitHit = git log -p -- package-lock.json yarn.lock 2>$null | Select-String -Pattern 'plain-crypto-js' | Select-Object -First 3
    if ($gitHit) {
      Flag "plain-crypto-js appeared in lockfile git history"
      $gitHit | ForEach-Object { Write-Host ("  " + $_.Line.Trim()) }
    } else {
      Ok "No trace of plain-crypto-js in lockfile history"
    }
  } else {
    Write-Host "  SKIP: git not found"
  }
} else {
  Write-Host "  SKIP: Not a git repository"
}

# 4) Malicious package in node_modules
Write-Section "[4/7] Checking for malicious package in node_modules..."
if (Test-Path "node_modules\plain-crypto-js") {
  Flag "node_modules\\plain-crypto-js exists"
} else {
  Ok "plain-crypto-js not present in node_modules"
}

# 5) Targeted search for suspicious references in common project files
Write-Section "[5/7] Searching common project files for suspicious references..."
$searchFiles = @('package.json','package-lock.json','npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml','.npmrc') |
  Where-Object { Test-Path $_ }
$refHits = @()
foreach ($f in $searchFiles) {
  $refHits += Select-String -Path $f -Pattern 'plain-crypto-js|sfrclak\.com|142\.11\.206\.73' -SimpleMatch:$false -ErrorAction SilentlyContinue
}
if ($refHits.Count -gt 0) {
  Flag "Suspicious references found in common project files"
  $refHits | Select-Object -First 20 | ForEach-Object { Write-Host ("  " + $_.Path + ':' + $_.LineNumber + ' ' + $_.Line.Trim()) }
} else {
  if ($searchFiles.Count -eq 0) {
    Write-Host "  SKIP: No common project files found in current directory"
  } else {
    Ok "No suspicious references found in common project files"
  }
}

# 6) Temp/artifact search on Windows
Write-Section "[6/7] Checking temp locations for obvious artifacts..."
$tempPaths = @($env:TEMP, 'C:\Windows\Temp') | Where-Object { $_ -and (Test-Path $_) }
$artifactHits = @()
foreach ($p in $tempPaths) {
  $artifactHits += Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'ld\.py|plain-crypto-js|axios' } |
    Select-Object -First 10 FullName
}
if ($artifactHits.Count -gt 0) {
  Flag "Potential artifact files found in temp paths"
  $artifactHits | Select-Object -Unique | ForEach-Object { Write-Host ("  " + $_.FullName) }
} else {
  Ok "No obvious temp artifacts found"
}

# 7) Network check
Write-Section "[7/7] Checking for active connections to known C2 IP..."
$netFound = $false
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
  $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -eq '142.11.206.73' }
  if ($tcp) {
    Flag "Active TCP connection to 142.11.206.73 detected"
    $tcp | Format-Table -AutoSize | Out-String | Write-Host
    $netFound = $true
  }
}
if (-not $netFound) {
  $netstatOut = netstat -ano 2>$null | Out-String
  if ($netstatOut -match '142\.11\.206\.73') {
    Flag "netstat shows connection to 142.11.206.73"
  } else {
    Ok "No active connection to 142.11.206.73 detected"
  }
}

Write-Host ""
Write-Host "============================================"
if ($FOUND) {
  Write-Host "  POTENTIAL COMPROMISE DETECTED"
  Write-Host ""
  Write-Host "  Immediate actions:"
  Write-Host "  1. Pin axios to 1.14.0 or 0.30.3"
  Write-Host "  2. Remove node_modules and reinstall from clean lockfile"
  Write-Host "  3. Rotate credentials if affected versions were installed"
  Write-Host "  4. Block sfrclak.com and 142.11.206.73"
  Write-Host "  5. Investigate git history and build logs"
} else {
  Write-Host "  ALL CLEAR: No indicators found by this Windows scan"
  Write-Host ""
  Write-Host "  Preventive steps:"
  Write-Host "  - Pin axios to a safe version"
  Write-Host "  - Prefer npm ci in CI/CD"
  Write-Host "  - Consider ignore-scripts=true where appropriate"
  Write-Host "  - Review lockfile changes before merges"
}
Write-Host "============================================"
