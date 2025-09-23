# Self-extracting Mermaid CLI launcher
# Extracts embedded zip on first run, then executes mmdc

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check if already extracted
if (-not (Test-Path "$scriptDir\node") -or -not (Test-Path "$scriptDir\node_modules")) {
    Write-Host "First run detected. Extracting Mermaid CLI..."
    
    $zipPath = "$scriptDir\mermaid-data.zip"
    
    if (Test-Path $zipPath) {
        try {
            # Extract the zip
            Expand-Archive -Path $zipPath -DestinationPath $scriptDir -Force
            Write-Host "Extraction complete."
            
            # Delete the zip file after successful extraction
            Remove-Item $zipPath -Force
            Write-Host "Cleaned up archive."
        }
        catch {
            Write-Error "Failed to extract: $_"
            exit 1
        }
    }
    else {
        Write-Error "mermaid-data.zip not found!"
        exit 1
    }
}

# Execute mmdc with all passed parameters
$nodePath = Join-Path $scriptDir "node\node.exe"
$mmdcPath = Join-Path $scriptDir "node_modules\.bin\mmdc"

& $nodePath $mmdcPath $args
