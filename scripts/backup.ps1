$ErrorActionPreference = "Stop"

if (-not $env:DATABASE_URL) {
  throw "DATABASE_URL must be set before creating a backup."
}

$root = Split-Path -Parent $PSScriptRoot
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupDirectory = Join-Path $root "backups"
$uploadDirectory = Join-Path $root "uploads"
$databaseBackup = Join-Path $backupDirectory "ubuzima-pharma-$timestamp.dump"
$imagesBackup = Join-Path $backupDirectory "ubuzima-pharma-images-$timestamp.zip"

New-Item -ItemType Directory -Force -Path $backupDirectory | Out-Null
& pg_dump --format=custom --file=$databaseBackup $env:DATABASE_URL
if ($LASTEXITCODE -ne 0) {
  throw "pg_dump failed; database backup was not completed."
}

$images = @(Get-ChildItem -File -Filter "*.webp" $uploadDirectory)
if ($images.Count -gt 0) {
  Compress-Archive -Path $images.FullName -DestinationPath $imagesBackup
}

Write-Output "Database backup: $databaseBackup"
if ($images.Count -gt 0) {
  Write-Output "Image backup: $imagesBackup"
} else {
  Write-Output "No uploaded images to back up."
}
