@echo off
setlocal enabledelayedexpansion
set "SCRIPT_DIR=%~dp0"

REM Check if already extracted
if not exist "%SCRIPT_DIR%node" (
    echo First run detected. Extracting Mermaid CLI...
    goto extract
)
if not exist "%SCRIPT_DIR%node_modules" (
    echo First run detected. Extracting Mermaid CLI...
    goto extract
)
goto run

:extract
if not exist "%SCRIPT_DIR%mermaid-data.zip" (
    echo ERROR: mermaid-data.zip not found!
    exit /b 1
)

REM Use PowerShell to unzip
powershell -NoProfile -Command "Expand-Archive -Path '%SCRIPT_DIR%mermaid-data.zip' -DestinationPath '%SCRIPT_DIR%' -Force"

if errorlevel 1 (
    echo ERROR: Failed to extract archive
    exit /b 1
)

echo Extraction complete.

REM Delete the zip file
del "%SCRIPT_DIR%mermaid-data.zip"
echo Cleaned up archive.

:run
REM Execute mmdc with all parameters
"%SCRIPT_DIR%node\node.exe" "%SCRIPT_DIR%node_modules\@mermaid-js\mermaid-cli\src\cli.js" %*
endlocal