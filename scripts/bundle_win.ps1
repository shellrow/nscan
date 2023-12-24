# build and bundle the nscan binary and license files into a zip file
# usage: 
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process (Only needed if not already set)
# .\scripts\bundle.ps1

$binName = "nscan.exe"
$version = "0.18.0"
$osArch = "x86_64-pc-windows-msvc"
$distDir = ".\dist"

$zipFilename = "nscan-$version-$osArch.zip"

Write-Host "Building nscan binary for $osArch"
cargo build --release

# if distDir does not exist, create it
if (-not (Test-Path -Path $distDir -PathType Container)) {
    New-Item -Path $distDir -ItemType Directory
}

Copy-Item -Path ".\target\release\$binName" -Destination "$distDir\$binName" -Force
Copy-Item -Path ".\LICENSE" -Destination "$distDir\LICENSE" -Force

Set-Location -Path $distDir
Write-Host "Creating zip file $zipFilename"
Compress-Archive -Path "$binName", "LICENSE" -DestinationPath $zipFilename
Write-Host "Done"
