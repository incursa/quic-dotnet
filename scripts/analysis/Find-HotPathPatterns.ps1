[CmdletBinding()]
param(
    [string[]] $Path = @(
        "src/Incursa.Quic",
        "src/Incursa.Quic.Http3",
        "src/Incursa.Qpack",
        "samples/Incursa.Http3.Samples.TechEmpower"
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "../..")
$resolvedPaths = foreach ($entry in $Path) {
    $candidate = Join-Path $repoRoot $entry
    if (Test-Path -LiteralPath $candidate) {
        Resolve-Path -LiteralPath $candidate
    }
}

if (-not $resolvedPaths) {
    throw "No input paths were found."
}

$patterns = @(
    [pscustomobject]@{ Name = "new byte[]"; Pattern = "new\s+byte\s*\[" },
    [pscustomobject]@{ Name = "MemoryStream"; Pattern = "new\s+MemoryStream" },
    [pscustomobject]@{ Name = "ToArray"; Pattern = "\.ToArray\s*\(" },
    [pscustomobject]@{ Name = "UTF8.GetString"; Pattern = "Encoding\.UTF8\.GetString" },
    [pscustomobject]@{ Name = "UTF8.GetBytes"; Pattern = "Encoding\.UTF8\.GetBytes" },
    [pscustomobject]@{ Name = "LINQ Select/Where/OrderBy/GroupBy"; Pattern = "\.(Select|Where|OrderBy|GroupBy|SelectMany)\s*\(" },
    [pscustomobject]@{ Name = "lock"; Pattern = "\block\s*\(" },
    [pscustomobject]@{ Name = "ConcurrentDictionary"; Pattern = "ConcurrentDictionary" },
    [pscustomobject]@{ Name = "Channel"; Pattern = "\bChannel\b|Channel<|ChannelReader|ChannelWriter" },
    [pscustomobject]@{ Name = "Task.Run"; Pattern = "Task\.Run\s*\(" },
    [pscustomobject]@{ Name = "WriteAsync"; Pattern = "\.WriteAsync\s*\(" },
    [pscustomobject]@{ Name = "FlushAsync"; Pattern = "\.FlushAsync\s*\(" },
    [pscustomobject]@{ Name = "Date formatting"; Pattern = "DateTimeOffset\.UtcNow|ToString\s*\(\s*""R""" },
    [pscustomobject]@{ Name = "CancellationToken registration"; Pattern = "\.Register\s*\(" }
)

$files = foreach ($resolvedPath in $resolvedPaths) {
    Get-ChildItem -LiteralPath $resolvedPath -Recurse -File -Include *.cs
}

foreach ($pattern in $patterns) {
    $matches = @(
        Select-String -Path $files.FullName -Pattern $pattern.Pattern -AllMatches -CaseSensitive |
            ForEach-Object {
                [pscustomobject]@{
                    Pattern = $pattern.Name
                    Path = (Resolve-Path -LiteralPath $_.Path -Relative)
                    Line = $_.LineNumber
                    Text = $_.Line.Trim()
                }
            }
    )

    Write-Output ""
    Write-Output ("## {0} ({1})" -f $pattern.Name, $matches.Count)
    foreach ($match in $matches) {
        Write-Output ("{0}:{1}: {2}" -f $match.Path, $match.Line, $match.Text)
    }
}
