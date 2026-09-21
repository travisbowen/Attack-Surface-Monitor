# Run manually from your own PowerShell after this task's commands have stopped.
# Only removes explicitly named setup directories created during lab verification.
# Supports -WhatIf to review targets without deleting them.
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$outputRoot = (Resolve-Path -LiteralPath (Join-Path $projectRoot 'out')).Path
$taskDirectories = @(
    'core-venv',
    'dependencies',
    'permission-check-63660d1e687d42af86440828a139ded3',
    'pyrit-src',
    'pyrit-venv',
    'pytest-cache',
    'pytest-cache-files-16gbeh3d',
    'test-temp',
    'uv-cache',
    'ai-triage-lab'
)

foreach ($directoryName in $taskDirectories) {
    $candidatePath = Join-Path $outputRoot $directoryName
    if (-not (Test-Path -LiteralPath $candidatePath)) { continue }
    $resolvedPath = (Resolve-Path -LiteralPath $candidatePath).Path
    if (-not $resolvedPath.StartsWith($outputRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing deletion outside the project output directory: $resolvedPath"
    }
    $directory = Get-Item -LiteralPath $resolvedPath -Force
    if (-not $directory.PSIsContainer -or ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing deletion of non-directory or redirected root: $resolvedPath"
    }
    if ($PSCmdlet.ShouldProcess($resolvedPath, 'Remove disposable task setup directory')) {
        Remove-Item -LiteralPath $resolvedPath -Recurse -Force
    }
}

# Deliberately preserves verified-lab, verified-import, pyrit-demo, original scan
# files, source changes, and all pre-existing workspaces. Never changes ACLs.
