# Mermaid CLI - Portable Self-Extracting Edition

A portable, no-installation-required version of [Mermaid CLI](https://github.com/mermaid-js/mermaid-cli) for Windows.

## Quick Start

1. **Extract** this zip file to any folder
2. **Run** `mmdc.bat` (or `mmdc.ps1`) with your command

On **first run only**, the tool will automatically extract its components (~150MB). This takes 10-30 seconds.

Subsequent runs execute immediately.

## Usage

### Batch Script (Recommended)
```cmd
mmdc.bat -i input.mmd -o output.png
```

### PowerShell Script
```powershell
.\mmdc.ps1 -i input.mmd -o output.png
```

## Examples

Generate different output formats:
```cmd
mmdc.bat -i diagram.mmd -o diagram.svg
mmdc.bat -i flowchart.mmd -o flowchart.pdf
mmdc.bat -i sequence.mmd -o sequence.png
```

Use dark theme:
```cmd
mmdc.bat -i diagram.mmd -o diagram.png -t dark
```

Specify background color:
```cmd
mmdc.bat -i diagram.mmd -o diagram.png -b "#1a1a1a"
```

## What Happens on First Run?

The launcher scripts check for required components (`node/` and `node_modules/`). If missing, they:

1. Extract `mermaid-data.zip` to the current directory
2. Delete the zip file to save space
3. Execute your mermaid command

The extraction only happens once. After that, it runs instantly.

## Contents

- `mmdc.bat` - Windows batch launcher (uses PowerShell for extraction)
- `mmdc.ps1` - Pure PowerShell launcher (alternative)
- `mermaid-data.zip` - Compressed Node.js runtime and mermaid-cli (~100MB compressed)
- `README.md` - This file

## System Requirements

- Windows 10 or later (PowerShell 5.0+)
- No Node.js installation required
- No administrator rights required

## Troubleshooting

**Permission errors**: Run from a folder where you have write permissions

**PowerShell execution policy error**: Run `mmdc.bat` instead, or set execution policy:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## License

This package includes:
- Mermaid CLI (Apache 2.0)
- Node.js (MIT)
- Various npm packages (see individual licenses)

## More Information

- [Mermaid Documentation](https://mermaid.js.org/)
- [Mermaid CLI Options](https://github.com/mermaid-js/mermaid-cli#options)