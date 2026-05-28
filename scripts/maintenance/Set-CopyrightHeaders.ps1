# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [int] $Year = 2026
)

$headerLines = @(
    "// Copyright (c) $Year Incursa LLC.",
    "// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information."
)

$excludedDirectories = @('.git', '.artifacts', 'bin', 'obj')
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Test-IsExcludedPath {
    param([string] $Path)

    $relative = [System.IO.Path]::GetRelativePath($Root, $Path)
    $parts = $relative -split '[\\/]'
    foreach ($directory in $excludedDirectories) {
        if ($parts -contains $directory) {
            return $true
        }
    }

    return $false
}

Get-ChildItem -Path $Root -Recurse -File -Filter '*.cs' |
    Where-Object { -not (Test-IsExcludedPath -Path $_.FullName) } |
    ForEach-Object {
        $path = $_.FullName
        $text = [System.IO.File]::ReadAllText($path)
        $newline = if ($text -match "`r`n") { "`r`n" } elseif ($text -match "`n") { "`n" } else { [Environment]::NewLine }
        $header = ($headerLines -join $newline) + $newline + $newline

        if ($text.StartsWith($header, [System.StringComparison]::Ordinal)) {
            return
        }

        if ($PSCmdlet.ShouldProcess($path, 'Apply Incursa LLC Apache copyright header')) {
            [System.IO.File]::WriteAllText($path, $header + $text.TrimStart(), $utf8NoBom)
        }
    }
