# axios-compromise-checker-windows

Windows PowerShell scanner for checking common indicators related to the axios supply chain compromise affecting `axios@1.14.1` and `axios@0.30.4`.

## What it checks

1. Installed axios versions via `npm list axios`
2. Lockfiles in a selected target directory for affected versions
3. Git history of lockfiles for `plain-crypto-js`
4. Presence of `node_modules\plain-crypto-js`
5. Common project files for suspicious references:
   - `plain-crypto-js`
   - `sfrclak.com`
   - `142.11.206.73`
6. Windows temp paths for obvious artifacts
7. Active network connections to `142.11.206.73`

## Why this exists

The original detection script being shared online was written for macOS/Linux and expects `bash`. This repo provides a Windows-native PowerShell equivalent that can be run directly on a Windows host.

## Usage

### Scan the current directory

```powershell
powershell -ExecutionPolicy Bypass -File .\check-axios-compromise.ps1
```

### Scan a specific project path

```powershell
powershell -ExecutionPolicy Bypass -File .\check-axios-compromise.ps1 -TargetPath "C:\path\to\project"
```

### Run the script from somewhere else against a project

```powershell
powershell -ExecutionPolicy Bypass -File C:\path\to\check-axios-compromise.ps1 -TargetPath "C:\path\to\project"
```

## Parameters

- `-TargetPath`
  - Optional
  - Defaults to the current working directory
  - Lets other people scan any local Node.js repo without moving the script into that repo

## Recommended usage pattern

Clone this repo anywhere on a Windows machine, then point `-TargetPath` at the Node.js project you actually want to inspect.

## Limitations

- This is a detection helper, not a forensic guarantee.
- It is strongest when run against a specific repository with lockfiles and `node_modules` present.
- It does not prove a machine is safe if prior compromise artifacts were removed.
- Windows-specific artifact checks are heuristic because the public reports focused more heavily on Linux/macOS payload paths.

## If indicators are found

1. Pin axios to a safe version
2. Remove `node_modules` and reinstall from a clean lockfile
3. Rotate secrets and credentials if affected versions were present
4. Review CI logs and git history
5. Investigate suspicious network activity

## Notes

This repo was created from a Windows-safe rewrite of a bash-based axios compromise checker so it can run in PowerShell-first environments.
