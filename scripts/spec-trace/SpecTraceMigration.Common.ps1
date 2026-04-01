Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SpecTraceMigrationRepoRoot {
    param(
        [string]$RootPath = (Join-Path $PSScriptRoot '..\..')
    )

    return (Resolve-Path -LiteralPath $RootPath).Path
}

function Get-NonEmptyArray {
    param([object]$Value)

    $values = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($Value)) {
        if ($item -is [System.Collections.IEnumerable] -and -not ($item -is [string]) -and -not ($item -is [System.Collections.IDictionary])) {
            foreach ($nestedItem in @($item)) {
                if ($null -ne $nestedItem -and -not [string]::IsNullOrWhiteSpace($nestedItem.ToString())) {
                    $values.Add($nestedItem)
                }
            }

            continue
        }

        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $values.Add($item)
        }
    }

    return $values.ToArray()
}

function Get-SpecTraceCanonicalMarkdownArtifactPaths {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [string[]]$Scope
    )

    $roots = @(
        'specs/requirements',
        'specs/architecture',
        'specs/work-items',
        'specs/verification'
    )

    $scopePrefixes = @($Scope | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
            $_.Trim().Replace('\', '/').TrimStart('/').TrimEnd('/')
        })

    foreach ($root in $roots) {
        $fullRoot = Join-Path $RepoRoot $root
        if (-not (Test-Path -LiteralPath $fullRoot)) {
            continue
        }

        foreach ($file in Get-ChildItem -LiteralPath $fullRoot -Recurse -File -Filter '*.md' | Sort-Object FullName) {
            if ($file.Name -in @('README.md', '_index.md', 'REQUIREMENT-GAPS.md')) {
                continue
            }

            $cueCompanion = [System.IO.Path]::ChangeExtension($file.FullName, '.cue')
            $jsonCompanion = [System.IO.Path]::ChangeExtension($file.FullName, '.json')
            if ((Test-Path -LiteralPath $cueCompanion) -or (Test-Path -LiteralPath $jsonCompanion)) {
                continue
            }

            $relativePath = Get-RepoRelativePath -RepoRoot $RepoRoot -Path $file.FullName
            if ($scopePrefixes.Count -gt 0 -and -not ($scopePrefixes | Where-Object { $relativePath.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) })) {
                continue
            }

            $file.FullName
        }
    }
}

function Get-SpecTraceCanonicalCueArtifactPaths {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [string[]]$Scope
    )

    $roots = @(
        'specs/requirements',
        'specs/architecture',
        'specs/work-items',
        'specs/verification'
    )

    $scopePrefixes = @($Scope | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
            $_.Trim().Replace('\', '/').TrimStart('/').TrimEnd('/')
        })

    foreach ($root in $roots) {
        $fullRoot = Join-Path $RepoRoot $root
        if (-not (Test-Path -LiteralPath $fullRoot)) {
            continue
        }

        foreach ($file in Get-ChildItem -LiteralPath $fullRoot -Recurse -File -Filter '*.cue' | Sort-Object FullName) {
            $relativePath = Get-RepoRelativePath -RepoRoot $RepoRoot -Path $file.FullName
            if ($scopePrefixes.Count -gt 0 -and -not ($scopePrefixes | Where-Object { $relativePath.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) })) {
                continue
            }

            $file.FullName
        }
    }
}

function Get-SpecTraceCanonicalJsonArtifactPaths {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [string[]]$Scope
    )

    $roots = @(
        'specs/requirements',
        'specs/architecture',
        'specs/work-items',
        'specs/verification'
    )

    $scopePrefixes = @($Scope | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
            $_.Trim().Replace('\', '/').TrimStart('/').TrimEnd('/')
        })

    foreach ($root in $roots) {
        $fullRoot = Join-Path $RepoRoot $root
        if (-not (Test-Path -LiteralPath $fullRoot)) {
            continue
        }

        foreach ($file in Get-ChildItem -LiteralPath $fullRoot -Recurse -File -Filter '*.json' | Sort-Object FullName) {
            $relativePath = Get-RepoRelativePath -RepoRoot $RepoRoot -Path $file.FullName
            if ($scopePrefixes.Count -gt 0 -and -not ($scopePrefixes | Where-Object { $relativePath.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) })) {
                continue
            }

            $file.FullName
        }
    }
}

function Get-SpecTraceCanonicalSourceArtifactPaths {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [string[]]$Scope
    )

    $roots = @(
        'specs/requirements',
        'specs/architecture',
        'specs/work-items',
        'specs/verification'
    )

    $scopePrefixes = @($Scope | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
            $_.Trim().Replace('\', '/').TrimStart('/').TrimEnd('/')
        })

    foreach ($root in $roots) {
        $fullRoot = Join-Path $RepoRoot $root
        if (-not (Test-Path -LiteralPath $fullRoot)) {
            continue
        }

        $grouped = @{}
        foreach ($file in Get-ChildItem -LiteralPath $fullRoot -Recurse -File | Sort-Object FullName) {
            if ($file.Extension -notin @('.json', '.cue', '.md')) {
                continue
            }

            if ($file.Name -in @('README.md', '_index.md', 'REQUIREMENT-GAPS.md')) {
                continue
            }

            $basePath = [System.IO.Path]::ChangeExtension($file.FullName, $null)
            if (-not $grouped.Contains($basePath)) {
                $grouped[$basePath] = @{}
            }

            $grouped[$basePath][$file.Extension.ToLowerInvariant()] = $file.FullName
        }

        foreach ($basePath in ($grouped.Keys | Sort-Object)) {
            $selectedPath = if ($grouped[$basePath].Contains('.json')) {
                $grouped[$basePath]['.json']
            }
            elseif ($grouped[$basePath].Contains('.cue')) {
                $grouped[$basePath]['.cue']
            }
            elseif ($grouped[$basePath].Contains('.md')) {
                $grouped[$basePath]['.md']
            }
            else {
                $null
            }

            if ($null -eq $selectedPath) {
                continue
            }

            $relativePath = Get-RepoRelativePath -RepoRoot $RepoRoot -Path $selectedPath
            if ($scopePrefixes.Count -gt 0 -and -not ($scopePrefixes | Where-Object { $relativePath.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) })) {
                continue
            }

            $selectedPath
        }
    }
}

function Get-RepoRelativePath {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [Parameter(Mandatory)]
        [string]$Path
    )

    return [System.IO.Path]::GetRelativePath($RepoRoot, $Path).Replace('\', '/')
}

function Normalize-MarkdownBlock {
    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    return (($Text -replace "`r`n", "`n" -replace "`r", "`n").Trim())
}

function Convert-MarkdownParagraphsToText {
    param(
        [AllowNull()]
        [string]$Text
    )

    $normalized = Normalize-MarkdownBlock -Text $Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $null
    }

    $paragraphs = New-Object System.Collections.Generic.List[string]
    foreach ($paragraph in [regex]::Split($normalized, "`n\s*`n")) {
        $trimmed = $paragraph.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        $joined = (($trimmed -split "`n") | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 }) -join ' '
        if ($joined.Length -gt 0) {
            $paragraphs.Add($joined)
        }
    }

    if ($paragraphs.Count -eq 0) {
        return $null
    }

    return ($paragraphs -join "`n`n")
}

function Read-FrontMatterDocument {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $content = Get-Content -LiteralPath $Path -Raw
    $normalized = $content -replace "`r`n", "`n" -replace "`r", "`n"
    if ($normalized -notmatch '^(?s)---\n(?<frontMatter>.*?)\n---\n(?<body>.*)$') {
        throw "Expected YAML front matter in '$Path'."
    }

    return [ordered]@{
        FrontMatter = Parse-SimpleFrontMatter -Text $matches.frontMatter
        Body        = $matches.body
    }
}

function Parse-SimpleFrontMatter {
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )

    $data = [ordered]@{}
    $currentKey = $null
    foreach ($rawLine in ($Text -split "`n")) {
        $line = $rawLine.TrimEnd()
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($line -match '^(?<key>[A-Za-z0-9_]+):\s*(?<value>.*)$') {
            $currentKey = $matches.key
            $value = $matches.value.Trim()
            if ($value.Length -eq 0) {
                $data[$currentKey] = New-Object System.Collections.ArrayList
            }
            else {
                $data[$currentKey] = $value
                $currentKey = $null
            }

            continue
        }

        if ($line -match '^\s*-\s+(?<value>.+)$') {
            if ($null -eq $currentKey) {
                throw "Unexpected front matter list item '$line'."
            }

            $list = $data[$currentKey]
            if ($list -isnot [System.Collections.IList]) {
                $list = New-Object System.Collections.ArrayList
                $data[$currentKey] = $list
            }

            [void]$list.Add($matches.value.Trim())
            continue
        }

        if ($null -ne $currentKey) {
            if ($data[$currentKey] -is [System.Collections.IList]) {
                $list = [System.Collections.IList]$data[$currentKey]
                if ($list.Count -eq 0) {
                    throw "Unexpected front matter continuation '$line'."
                }

                $list[$list.Count - 1] = "$($list[$list.Count - 1]) $($line.Trim())"
            }
            else {
                $data[$currentKey] = "$( $data[$currentKey]) $($line.Trim())".Trim()
            }

            continue
        }

        throw "Unexpected front matter line '$line'."
    }

    return $data
}

function Get-MarkdownH2Sections {
    param(
        [Parameter(Mandatory)]
        [string]$Body
    )

    $sections = New-Object System.Collections.Generic.List[object]
    $heading = $null
    $buffer = New-Object System.Collections.Generic.List[string]
    foreach ($line in (($Body -replace "`r`n", "`n" -replace "`r", "`n") -split "`n")) {
        if ($line -match '^##\s+(?<heading>.+?)\s*$') {
            if ($null -ne $heading) {
                $sections.Add([ordered]@{
                        Heading = $heading
                        Body    = ($buffer -join "`n").Trim()
                    })
            }

            $heading = $matches.heading.Trim()
            $buffer = New-Object System.Collections.Generic.List[string]
            continue
        }

        if ($null -ne $heading) {
            $buffer.Add($line)
        }
    }

    if ($null -ne $heading) {
        $sections.Add([ordered]@{
                Heading = $heading
                Body    = ($buffer -join "`n").Trim()
            })
    }

    return $sections
}

function Try-ParseRequirementHeading {
    param(
        [Parameter(Mandatory)]
        [string]$Heading
    )

    if ($Heading -match '^\[`?(?<id>REQ-[A-Z0-9-]+)`?\]\([^)]+\)\s*(?:-\s*)?(?<title>.*)$') {
        return [ordered]@{
            Id    = $matches.id.Trim()
            Title = $matches.title.Trim()
        }
    }

    if ($Heading -match '^(?<id>REQ-[A-Z0-9-]+)\s+(?<title>.+)$') {
        return [ordered]@{
            Id    = $matches.id.Trim()
            Title = $matches.title.Trim()
        }
    }

    return $null
}

function Get-MarkdownLinkParts {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    if ($Value -match '^\[(?<label>.+?)\]\((?<target>.+?)\)$') {
        return [ordered]@{
            Label  = $matches.label.Trim()
            Target = $matches.target.Trim()
        }
    }

    return $null
}

function Strip-MarkdownCodeTicks {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Value
    }

    return $Value.Trim().Trim('`')
}

function Convert-ToRepoRelativeReference {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$Value
    )

    $candidate = $Value.Trim().Trim('<', '>', "'", '"')
    if ($candidate -match '^[a-zA-Z][a-zA-Z0-9+\-.]*://') {
        return $candidate
    }

    if ([System.IO.Path]::IsPathRooted($candidate)) {
        return Get-RepoRelativePath -RepoRoot $RepoRoot -Path $candidate
    }

    if ($candidate.StartsWith('./', [System.StringComparison]::Ordinal) -or
        $candidate.StartsWith('../', [System.StringComparison]::Ordinal)) {
        $fullPath = [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $SourcePath) $candidate))
        return Get-RepoRelativePath -RepoRoot $RepoRoot -Path $fullPath
    }

    return $candidate.Replace('\', '/').TrimStart('/')
}

function Normalize-TypedTraceValue {
    param(
        [Parameter(Mandatory)]
        [string]$Value,

        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [Parameter(Mandatory)]
        [string]$SourcePath
    )

    $trimmed = Strip-MarkdownCodeTicks -Value $Value
    $link = Get-MarkdownLinkParts -Value $trimmed
    if ($null -ne $link) {
        $label = Strip-MarkdownCodeTicks -Value $link.Label
        if ($label -match '^(REQ|SPEC|ARC|WI|VER)-[A-Z0-9-]+$') {
            return $label
        }

        $target = Convert-ToRepoRelativeReference -RepoRoot $RepoRoot -SourcePath $SourcePath -Value $link.Target
        $fileStem = [System.IO.Path]::GetFileNameWithoutExtension($target)
        if ($fileStem -match '^(REQ|SPEC|ARC|WI|VER)-[A-Z0-9-]+$') {
            return $fileStem
        }

        return $label
    }

    return $trimmed
}

function Convert-SectionToTraceValue {
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [Parameter(Mandatory)]
        [string]$Value,

        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [Parameter(Mandatory)]
        [string]$SourcePath
    )

    switch ($Label) {
        'Satisfied By' { return Normalize-TypedTraceValue -Value $Value -RepoRoot $RepoRoot -SourcePath $SourcePath }
        'Implemented By' { return Normalize-TypedTraceValue -Value $Value -RepoRoot $RepoRoot -SourcePath $SourcePath }
        'Verified By' { return Normalize-TypedTraceValue -Value $Value -RepoRoot $RepoRoot -SourcePath $SourcePath }
        'Derived From' { return Normalize-TypedTraceValue -Value $Value -RepoRoot $RepoRoot -SourcePath $SourcePath }
        'Supersedes' { return Normalize-TypedTraceValue -Value $Value -RepoRoot $RepoRoot -SourcePath $SourcePath }
        'Related' { return Normalize-TypedTraceValue -Value $Value -RepoRoot $RepoRoot -SourcePath $SourcePath }
        default { return $Value.Trim() }
    }
}

function Convert-TraceLabelToCueKey {
    param(
        [Parameter(Mandatory)]
        [string]$Label
    )

    switch ($Label) {
        'Satisfied By' { return 'satisfied_by' }
        'Implemented By' { return 'implemented_by' }
        'Verified By' { return 'verified_by' }
        'Derived From' { return 'derived_from' }
        'Supersedes' { return 'supersedes' }
        'Source Refs' { return 'upstream_refs' }
        'Test Refs' { return 'test_refs' }
        'Code Refs' { return 'code_refs' }
        'Related' { return 'related' }
        default { return (Normalize-SectionKey -Heading $Label) }
    }
}

function Convert-CueKeyToTraceLabel {
    param(
        [Parameter(Mandatory)]
        [string]$Key
    )

    switch ($Key) {
        'satisfied_by' { return 'Satisfied By' }
        'implemented_by' { return 'Implemented By' }
        'verified_by' { return 'Verified By' }
        'derived_from' { return 'Derived From' }
        'supersedes' { return 'Supersedes' }
        'upstream_refs' { return 'Source Refs' }
        'test_refs' { return 'Test Refs' }
        'code_refs' { return 'Code Refs' }
        'related' { return 'Related' }
        default { return $Key }
    }
}

function Parse-TraceBlock {
    param(
        [AllowNull()]
        [string]$Text,

        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [Parameter(Mandatory)]
        [string]$SourcePath
    )

    $normalized = Normalize-MarkdownBlock -Text $Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $null
    }

    $rawLabels = [ordered]@{}
    $currentLabel = $null
    foreach ($rawLine in ($normalized -split "`n")) {
        $line = $rawLine.TrimEnd()
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($line -match '^\s*-\s+(?<label>[^:]+):\s*$') {
            $currentLabel = $matches.label.Trim()
            if (-not $rawLabels.Contains($currentLabel)) {
                $rawLabels[$currentLabel] = New-Object System.Collections.ArrayList
            }

            continue
        }

        if ($line -match '^\s*-\s+(?<value>.+?)\s*$') {
            if ($null -eq $currentLabel) {
                throw "Unexpected trace value '$line' in '$SourcePath'."
            }

            [void]$rawLabels[$currentLabel].Add($matches.value.Trim())
            continue
        }

        if ($null -ne $currentLabel) {
            $values = [System.Collections.IList]$rawLabels[$currentLabel]
            if ($values.Count -eq 0) {
                throw "Unexpected trace continuation '$line' in '$SourcePath'."
            }

            $values[$values.Count - 1] = "$($values[$values.Count - 1]) $($line.Trim())"
            continue
        }

        throw "Unexpected trace line '$line' in '$SourcePath'."
    }

    $trace = [ordered]@{}
    foreach ($label in $rawLabels.Keys) {
        $key = Convert-TraceLabelToCueKey -Label $label
        $values = @($rawLabels[$label] | ForEach-Object {
                Convert-SectionToTraceValue -Label $label -Value $_ -RepoRoot $RepoRoot -SourcePath $SourcePath
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($values.Count -gt 0) {
            $trace[$key] = $values
        }
    }

    if ($trace.Count -eq 0) {
        return $null
    }

    return $trace
}

function Parse-RequirementBody {
    param(
        [AllowNull()]
        [string]$Text,

        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [Parameter(Mandatory)]
        [string]$SourcePath
    )

    $statementBuffer = New-Object System.Collections.Generic.List[string]
    $traceBuffer = New-Object System.Collections.Generic.List[string]
    $notesBuffer = New-Object System.Collections.Generic.List[string]
    $mode = 'statement'

    foreach ($rawLine in (($Text -replace "`r`n", "`n" -replace "`r", "`n") -split "`n")) {
        $trimmed = $rawLine.Trim()
        if ($trimmed -eq 'Trace:') {
            $mode = 'trace'
            continue
        }

        if ($trimmed -eq 'Notes:') {
            $mode = 'notes'
            continue
        }

        switch ($mode) {
            'statement' { $statementBuffer.Add($rawLine) }
            'trace' { $traceBuffer.Add($rawLine) }
            'notes' { $notesBuffer.Add($rawLine) }
        }
    }

    return [ordered]@{
        statement      = Convert-MarkdownParagraphsToText -Text ($statementBuffer -join "`n")
        trace          = Parse-TraceBlock -Text ($traceBuffer -join "`n") -RepoRoot $RepoRoot -SourcePath $SourcePath
        notes_markdown = Normalize-MarkdownBlock -Text ($notesBuffer -join "`n")
    }
}

function Normalize-SectionKey {
    param(
        [Parameter(Mandatory)]
        [string]$Heading
    )

    $key = $Heading.ToLowerInvariant() -replace '[^a-z0-9]+', '_'
    return $key.Trim('_')
}

function Parse-MarkdownListSection {
    param(
        [AllowNull()]
        [string]$Text
    )

    $normalized = Normalize-MarkdownBlock -Text $Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return @()
    }

    $items = New-Object System.Collections.Generic.List[string]
    $current = $null
    foreach ($rawLine in ($normalized -split "`n")) {
        $line = $rawLine.TrimEnd()
        if ($line -match '^\s*-\s+(?<value>.+?)\s*$') {
            if ($null -ne $current) {
                $items.Add($current.Trim())
            }

            $current = $matches.value.Trim()
            continue
        }

        if ($null -ne $current) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $current = "$current $($line.Trim())"
        }
    }

    if ($null -ne $current) {
        $items.Add($current.Trim())
    }

    return $items.ToArray()
}

function Convert-MarkdownBlockToStringList {
    param(
        [AllowNull()]
        [string]$Text
    )

    $normalized = Normalize-MarkdownBlock -Text $Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return @()
    }

    $items = @(Parse-MarkdownListSection -Text $normalized)
    if ($items.Count -gt 0) {
        return $items
    }

    $paragraphs = New-Object System.Collections.Generic.List[string]
    foreach ($paragraph in ($normalized -split '(?:\n\s*\n)+')) {
        $value = (($paragraph -split "`n" | ForEach-Object { $_.Trim() }) | Where-Object { $_.Length -gt 0 }) -join ' '
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $paragraphs.Add($value)
        }
    }

    return $paragraphs.ToArray()
}

function Convert-LegacyTraceToPublishedSchema {
    param(
        [AllowNull()]
        [System.Collections.IDictionary]$Trace
    )

    if ($null -eq $Trace -or $Trace.Count -eq 0) {
        return $null
    }

    $publishedTrace = [ordered]@{}
    foreach ($key in @('satisfied_by', 'implemented_by', 'verified_by', 'derived_from', 'supersedes', 'upstream_refs', 'related')) {
        if (-not $Trace.Contains($key)) {
            continue
        }

        $values = @(Get-NonEmptyArray -Value $Trace[$key])
        if ($values.Count -gt 0) {
            $publishedTrace[$key] = $values
        }
    }

    if ($Trace.Contains('test_refs')) {
        $values = @(Get-NonEmptyArray -Value $Trace['test_refs'])
        if ($values.Count -gt 0) {
            $publishedTrace['x_test_refs'] = $values
        }
    }

    if ($Trace.Contains('code_refs')) {
        $values = @(Get-NonEmptyArray -Value $Trace['code_refs'])
        if ($values.Count -gt 0) {
            $publishedTrace['x_code_refs'] = $values
        }
    }

    foreach ($key in @('x_test_refs', 'x_code_refs')) {
        if (-not $Trace.Contains($key)) {
            continue
        }

        $values = @(Get-NonEmptyArray -Value $Trace[$key])
        if ($values.Count -gt 0) {
            $publishedTrace[$key] = $values
        }
    }

    foreach ($key in $Trace.Keys | Where-Object { $_ -match '^x_[A-Za-z0-9_]+$' -and $_ -notin @('x_test_refs', 'x_code_refs') }) {
        if ($publishedTrace.Contains($key)) {
            continue
        }

        $values = @(Get-NonEmptyArray -Value $Trace[$key])
        if ($values.Count -gt 0) {
            $publishedTrace[$key] = $values
        }
    }

    if ($publishedTrace.Count -eq 0) {
        return $null
    }

    return $publishedTrace
}

function Convert-LegacyRequirementToPublishedSchema {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Requirement
    )

    $publishedRequirement = [ordered]@{
        id        = $Requirement['id']
        title     = $Requirement['title']
        statement = $Requirement['statement']
    }

    if ($Requirement.Contains('trace')) {
        $trace = Convert-LegacyTraceToPublishedSchema -Trace $Requirement['trace']
        if ($null -ne $trace) {
            $publishedRequirement['trace'] = $trace
        }
    }

    if ($Requirement.Contains('notes')) {
        $notes = @(Get-NonEmptyArray -Value $Requirement['notes'])
        if ($notes.Count -gt 0) {
            $publishedRequirement['notes'] = $notes
        }
    }
    elseif ($Requirement.Contains('notes_markdown')) {
        $notes = @(Convert-MarkdownBlockToStringList -Text $Requirement['notes_markdown'])
        if ($notes.Count -gt 0) {
            $publishedRequirement['notes'] = $notes
        }
    }

    foreach ($key in $Requirement.Keys | Where-Object { $_ -match '^x_[A-Za-z0-9_]+$' }) {
        $publishedRequirement[$key] = $Requirement[$key]
    }

    return $publishedRequirement
}

function Normalize-SupplementalSectionList {
    param([object]$Sections)

    $normalizedSections = New-Object System.Collections.Generic.List[object]
    foreach ($section in @(Get-NonEmptyArray -Value $Sections)) {
        if ($null -eq $section -or -not ($section -is [System.Collections.IDictionary])) {
            continue
        }

        $heading = $section['heading']
        $content = $section['content']
        if ([string]::IsNullOrWhiteSpace($heading) -or [string]::IsNullOrWhiteSpace($content)) {
            continue
        }

        $normalizedSection = [ordered]@{
            heading = $heading.Trim()
            content = $content.Trim()
        }

        foreach ($key in $section.Keys | Where-Object { $_ -match '^x_[A-Za-z0-9_]+$' }) {
            $normalizedSection[$key] = $section[$key]
        }

        $normalizedSections.Add($normalizedSection)
    }

    return $normalizedSections.ToArray()
}

function Convert-PublishedArtifactToNormalizedSchema {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Artifact,

        [Parameter(Mandatory)]
        [string]$SchemaUri
    )

    $publishedArtifact = [ordered]@{
        '$schema'      = $SchemaUri
        artifact_id    = $Artifact['artifact_id']
        artifact_type  = $Artifact['artifact_type']
        title          = $Artifact['title']
        domain         = $Artifact['domain']
        status         = $Artifact['status']
        owner          = $Artifact['owner']
    }

    switch ($Artifact['artifact_type']) {
        'specification' {
            $publishedArtifact['capability'] = $Artifact['capability']

            foreach ($key in @('tags', 'related_artifacts', 'open_questions')) {
                if ($Artifact.Contains($key)) {
                    $values = @(Get-NonEmptyArray -Value $Artifact[$key])
                    if ($values.Count -gt 0) {
                        $publishedArtifact[$key] = $values
                    }
                }
            }

            foreach ($key in @('purpose', 'scope', 'context')) {
                if ($Artifact.Contains($key) -and -not [string]::IsNullOrWhiteSpace($Artifact[$key])) {
                    $publishedArtifact[$key] = $Artifact[$key].Trim()
                }
            }

            $supplementalSections = @(Normalize-SupplementalSectionList -Sections $Artifact['supplemental_sections'])
            if ($supplementalSections.Count -gt 0) {
                $publishedArtifact['supplemental_sections'] = $supplementalSections
            }

            $publishedArtifact['requirements'] = @($Artifact['requirements'] | ForEach-Object {
                    Convert-LegacyRequirementToPublishedSchema -Requirement $_
                })
        }
        'architecture' {
            foreach ($key in @('related_artifacts', 'satisfies', 'key_components', 'edge_cases_and_constraints', 'alternatives_considered', 'risks', 'open_questions')) {
                if ($Artifact.Contains($key)) {
                    $values = @(Get-NonEmptyArray -Value $Artifact[$key])
                    if ($values.Count -gt 0) {
                        $publishedArtifact[$key] = $values
                    }
                }
            }

            foreach ($key in @('purpose', 'design_summary', 'data_and_state_considerations')) {
                if ($Artifact.Contains($key) -and -not [string]::IsNullOrWhiteSpace($Artifact[$key])) {
                    $publishedArtifact[$key] = $Artifact[$key].Trim()
                }
            }

            $supplementalSections = @(Normalize-SupplementalSectionList -Sections $Artifact['supplemental_sections'])
            if ($supplementalSections.Count -gt 0) {
                $publishedArtifact['supplemental_sections'] = $supplementalSections
            }
        }
        'work_item' {
            foreach ($key in @('related_artifacts', 'addresses', 'design_links', 'verification_links', 'out_of_scope')) {
                if ($Artifact.Contains($key)) {
                    $values = @(Get-NonEmptyArray -Value $Artifact[$key])
                    if ($values.Count -gt 0) {
                        $publishedArtifact[$key] = $values
                    }
                }
            }

            foreach ($key in @('summary', 'planned_changes', 'verification_plan', 'completion_notes')) {
                if ($Artifact.Contains($key) -and -not [string]::IsNullOrWhiteSpace($Artifact[$key])) {
                    $publishedArtifact[$key] = $Artifact[$key].Trim()
                }
            }

            $supplementalSections = @(Normalize-SupplementalSectionList -Sections $Artifact['supplemental_sections'])
            if ($supplementalSections.Count -gt 0) {
                $publishedArtifact['supplemental_sections'] = $supplementalSections
            }
        }
        'verification' {
            foreach ($key in @('verifies', 'evidence', 'related_artifacts', 'preconditions', 'procedure')) {
                if ($Artifact.Contains($key)) {
                    $values = @(Get-NonEmptyArray -Value $Artifact[$key])
                    if ($values.Count -gt 0) {
                        $publishedArtifact[$key] = $values
                    }
                }
            }

            foreach ($key in @('scope', 'verification_method', 'expected_result', 'status_summary')) {
                if ($Artifact.Contains($key) -and -not [string]::IsNullOrWhiteSpace($Artifact[$key])) {
                    $publishedArtifact[$key] = $Artifact[$key].Trim()
                }
            }

            $supplementalSections = @(Normalize-SupplementalSectionList -Sections $Artifact['supplemental_sections'])
            if ($supplementalSections.Count -gt 0) {
                $publishedArtifact['supplemental_sections'] = $supplementalSections
            }
        }
        default {
            throw "Unsupported artifact type '$($Artifact['artifact_type'])'."
        }
    }

    foreach ($key in $Artifact.Keys | Where-Object { $_ -match '^x_[A-Za-z0-9_]+$' }) {
        $publishedArtifact[$key] = $Artifact[$key]
    }

    return $publishedArtifact
}

function Convert-LegacySectionsToSupplementalSections {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Artifact,

        [string[]]$ExcludeSectionKeys = @()
    )

    if (-not $Artifact.Contains('sections')) {
        return @()
    }

    $excluded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($sectionKey in @($ExcludeSectionKeys)) {
        if (-not [string]::IsNullOrWhiteSpace($sectionKey)) {
            [void]$excluded.Add($sectionKey)
        }
    }

    $supplementalSections = New-Object System.Collections.Generic.List[object]
    $sectionKeys = if ($Artifact.Contains('section_order')) { @($Artifact['section_order']) } else { @($Artifact['sections'].Keys) }
    foreach ($sectionKey in $sectionKeys) {
        if ($excluded.Contains($sectionKey)) {
            continue
        }

        $content = $Artifact['sections'][$sectionKey]
        if ([string]::IsNullOrWhiteSpace($content)) {
            continue
        }

        $supplementalSections.Add([ordered]@{
                heading = Get-SectionTitleFromArtifact -Artifact $Artifact -SectionKey $sectionKey
                content = $content.Trim()
            })
    }

    return $supplementalSections.ToArray()
}

function Convert-LegacyArtifactToPublishedSchema {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Artifact,

        [Parameter(Mandatory)]
        [string]$SchemaUri
    )

    $hasLegacySectionModel = $Artifact.Contains('sections') -or $Artifact.Contains('section_order') -or $Artifact.Contains('section_titles')
    if (-not $hasLegacySectionModel) {
        return Convert-PublishedArtifactToNormalizedSchema -Artifact $Artifact -SchemaUri $SchemaUri
    }

    $publishedArtifact = [ordered]@{
        '$schema'      = $SchemaUri
        artifact_id    = $Artifact['artifact_id']
        artifact_type  = $Artifact['artifact_type']
        title          = $Artifact['title']
        domain         = $Artifact['domain']
        status         = $Artifact['status']
        owner          = $Artifact['owner']
    }

    foreach ($key in @('capability', 'tags', 'related_artifacts', 'satisfies', 'addresses', 'design_links', 'verification_links', 'verifies', 'evidence')) {
        if ($Artifact.Contains($key)) {
            $publishedArtifact[$key] = $Artifact[$key]
        }
    }

    $sections = if ($Artifact.Contains('sections')) { $Artifact['sections'] } else { @{} }

    switch ($Artifact['artifact_type']) {
        'specification' {
            $publishedArtifact['capability'] = $Artifact['capability']
            foreach ($key in @('purpose', 'scope', 'context')) {
                if ($sections.Contains($key) -and -not [string]::IsNullOrWhiteSpace($sections[$key])) {
                    $publishedArtifact[$key] = $sections[$key].Trim()
                }
            }

            if ($sections.Contains('open_questions')) {
                $openQuestions = @(Convert-MarkdownBlockToStringList -Text $sections['open_questions'])
                if ($openQuestions.Count -gt 0) {
                    $publishedArtifact['open_questions'] = $openQuestions
                }
            }

            $supplementalSections = @(Convert-LegacySectionsToSupplementalSections -Artifact $Artifact -ExcludeSectionKeys @('purpose', 'scope', 'context', 'open_questions'))
            if ($supplementalSections.Count -gt 0) {
                $publishedArtifact['supplemental_sections'] = $supplementalSections
            }

            $publishedArtifact['requirements'] = @($Artifact['requirements'] | ForEach-Object {
                    Convert-LegacyRequirementToPublishedSchema -Requirement $_
                })
        }
        'architecture' {
            $publishedArtifact['purpose'] = $sections['purpose'].Trim()
            $publishedArtifact['design_summary'] = $sections['design_summary'].Trim()

            foreach ($key in @('key_components', 'edge_cases_and_constraints', 'alternatives_considered', 'risks', 'open_questions')) {
                if ($sections.Contains($key)) {
                    $values = @(Convert-MarkdownBlockToStringList -Text $sections[$key])
                    if ($values.Count -gt 0) {
                        $publishedArtifact[$key] = $values
                    }
                }
            }

            if ($sections.Contains('data_and_state_considerations') -and -not [string]::IsNullOrWhiteSpace($sections['data_and_state_considerations'])) {
                $publishedArtifact['data_and_state_considerations'] = $sections['data_and_state_considerations'].Trim()
            }

            $supplementalSections = @(Convert-LegacySectionsToSupplementalSections -Artifact $Artifact -ExcludeSectionKeys @(
                    'purpose',
                    'requirements_satisfied',
                    'design_summary',
                    'key_components',
                    'data_and_state_considerations',
                    'edge_cases_and_constraints',
                    'alternatives_considered',
                    'risks',
                    'open_questions'))
            if ($supplementalSections.Count -gt 0) {
                $publishedArtifact['supplemental_sections'] = $supplementalSections
            }
        }
        'work_item' {
            foreach ($key in @('summary', 'planned_changes', 'verification_plan', 'completion_notes')) {
                if ($sections.Contains($key) -and -not [string]::IsNullOrWhiteSpace($sections[$key])) {
                    $publishedArtifact[$key] = $sections[$key].Trim()
                }
            }

            if ($sections.Contains('out_of_scope')) {
                $values = @(Convert-MarkdownBlockToStringList -Text $sections['out_of_scope'])
                if ($values.Count -gt 0) {
                    $publishedArtifact['out_of_scope'] = $values
                }
            }

            $supplementalSections = @(Convert-LegacySectionsToSupplementalSections -Artifact $Artifact -ExcludeSectionKeys @(
                    'summary',
                    'requirements_addressed',
                    'design_inputs',
                    'planned_changes',
                    'out_of_scope',
                    'verification_plan',
                    'completion_notes',
                    'trace_links'))
            if ($supplementalSections.Count -gt 0) {
                $publishedArtifact['supplemental_sections'] = $supplementalSections
            }
        }
        'verification' {
            foreach ($key in @('scope', 'verification_method', 'expected_result')) {
                if ($sections.Contains($key) -and -not [string]::IsNullOrWhiteSpace($sections[$key])) {
                    $publishedArtifact[$key] = $sections[$key].Trim()
                }
            }

            foreach ($key in @('preconditions', 'procedure_or_approach')) {
                if ($sections.Contains($key)) {
                    $targetKey = if ($key -eq 'procedure_or_approach') { 'procedure' } else { $key }
                    $values = @(Convert-MarkdownBlockToStringList -Text $sections[$key])
                    if ($values.Count -gt 0) {
                        $publishedArtifact[$targetKey] = $values
                    }
                }
            }

            if ($sections.Contains('status') -and -not [string]::IsNullOrWhiteSpace($sections['status'])) {
                $statusSummary = $sections['status'].Trim()
                if ($statusSummary -ne $Artifact['status']) {
                    $publishedArtifact['status_summary'] = $statusSummary
                }
            }

            $supplementalSections = @(Convert-LegacySectionsToSupplementalSections -Artifact $Artifact -ExcludeSectionKeys @(
                    'scope',
                    'requirements_verified',
                    'verification_method',
                    'preconditions',
                    'procedure_or_approach',
                    'expected_result',
                    'status',
                    'related_artifacts'))
            if ($supplementalSections.Count -gt 0) {
                $publishedArtifact['supplemental_sections'] = $supplementalSections
            }
        }
        default {
            throw "Unsupported artifact type '$($Artifact['artifact_type'])'."
        }
    }

    foreach ($key in $Artifact.Keys | Where-Object { $_ -match '^x_[A-Za-z0-9_]+$' }) {
        $publishedArtifact[$key] = $Artifact[$key]
    }

    return $publishedArtifact
}

function New-ArtifactModelFromMarkdown {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$RepoRoot
    )

    $document = Read-FrontMatterDocument -Path $Path
    $frontMatter = $document.FrontMatter
    $body = $document.Body

    $artifact = [ordered]@{
        artifact_id   = $frontMatter['artifact_id']
        artifact_type = $frontMatter['artifact_type']
        title         = $frontMatter['title']
        domain        = $frontMatter['domain']
        status        = $frontMatter['status']
        owner         = $frontMatter['owner']
    }

    if ($frontMatter.Contains('capability')) {
        $artifact['capability'] = $frontMatter['capability']
    }

    foreach ($key in @('related_artifacts', 'tags', 'satisfies', 'addresses', 'design_links', 'verification_links', 'verifies')) {
        if ($frontMatter.Contains($key)) {
            $artifact[$key] = @($frontMatter[$key])
        }
    }

    $sections = [ordered]@{}
    $sectionTitles = [ordered]@{}
    $sectionOrder = New-Object System.Collections.Generic.List[string]
    $requirements = New-Object System.Collections.Generic.List[object]

    foreach ($section in (Get-MarkdownH2Sections -Body $body)) {
        $requirementHeading = Try-ParseRequirementHeading -Heading $section.Heading
        if ($null -ne $requirementHeading) {
            $parsedRequirement = Parse-RequirementBody -Text $section.Body -RepoRoot $RepoRoot -SourcePath $Path
            $requirement = [ordered]@{
                id        = $requirementHeading.Id
                title     = $requirementHeading.Title
                statement = $parsedRequirement.statement
            }

            if ($null -ne $parsedRequirement.trace) {
                $requirement['trace'] = $parsedRequirement.trace
            }

            if (-not [string]::IsNullOrWhiteSpace($parsedRequirement.notes_markdown)) {
                $requirement['notes_markdown'] = $parsedRequirement.notes_markdown
            }

            $requirements.Add($requirement)
            continue
        }

        $sectionKey = Normalize-SectionKey -Heading $section.Heading
        $sectionOrder.Add($sectionKey)
        $sectionTitles[$sectionKey] = $section.Heading
        $sections[$sectionKey] = Normalize-MarkdownBlock -Text $section.Body
    }

    if ($sectionOrder.Count -gt 0) {
        $artifact['section_order'] = $sectionOrder.ToArray()
        $artifact['section_titles'] = $sectionTitles
        $artifact['sections'] = $sections
    }

    if ($requirements.Count -gt 0) {
        $artifact['requirements'] = $requirements.ToArray()
    }

    if (($artifact['artifact_type']) -eq 'verification' -and $sections.Contains('evidence')) {
        $artifact['evidence'] = @(
            Parse-MarkdownListSection -Text $sections['evidence'] | ForEach-Object {
                $value = $_.Trim()
                $link = Get-MarkdownLinkParts -Value $value
                if ($null -ne $link) {
                    return Convert-ToRepoRelativeReference -RepoRoot $RepoRoot -SourcePath $Path -Value $link.Target
                }

                return $value
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }

    return $artifact
}

function Convert-ArtifactToCueText {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Artifact
    )

    $definition = switch ($Artifact['artifact_type']) {
        'specification' { '#Specification' }
        'architecture' { '#Architecture' }
        'work_item' { '#WorkItem' }
        'verification' { '#Verification' }
        default { throw "Unsupported artifact type '$($Artifact['artifact_type'])'." }
    }

    $json = $Artifact | ConvertTo-Json -Depth 100
    $package = ($Artifact['domain'].ToString().ToLowerInvariant() -replace '[^a-z0-9]+', '')
    if ([string]::IsNullOrWhiteSpace($package)) {
        $package = 'spectrace'
    }

    return @"
package $package

import "github.com/incursa/quic-dotnet/cue/spectrace"

schema: spectrace.$definition

artifact: $json
"@
}

function Get-CueCompanionPath {
    param(
        [Parameter(Mandatory)]
        [string]$MarkdownPath
    )

    return [System.IO.Path]::ChangeExtension($MarkdownPath, '.cue')
}

function Get-MarkdownCompanionPath {
    param(
        [Parameter(Mandatory)]
        [string]$CuePath
    )

    return [System.IO.Path]::ChangeExtension($CuePath, '.md')
}

function Get-CueExecutablePath {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot
    )

    $cueCommand = Get-Command cue -ErrorAction SilentlyContinue
    if ($null -eq $cueCommand) {
        throw "Could not resolve 'cue'. Install the CUE CLI only if you need to convert legacy .cue artifacts."
    }

    return $cueCommand.Source
}

function Get-StandaloneCueArtifactText {
    param(
        [Parameter(Mandatory)]
        [string]$CuePath
    )

    $content = Get-Content -LiteralPath $CuePath -Raw
    $content = $content -replace '(?m)^\s*import\s+.+\r?\n', ''
    $content = $content -replace '(?m)^\s*schema:\s*.+\r?\n', ''
    $content = $content -replace 'artifact:\s*[A-Za-z0-9_.#]+\s*&\s*\{', 'artifact: {'
    return ($content.Trim() + [Environment]::NewLine)
}

function Export-CueArtifact {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [Parameter(Mandatory)]
        [string]$CuePath,

        [Parameter(Mandatory)]
        [string]$CueExecutable
    )

    $output = & $CueExecutable export $CuePath -e artifact --out json 2>&1
    if ($LASTEXITCODE -ne 0) {
        $temporaryCuePath = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), '.cue')
        try {
            [System.IO.File]::WriteAllText($temporaryCuePath, (Get-StandaloneCueArtifactText -CuePath $CuePath))
            $output = & $CueExecutable export $temporaryCuePath -e artifact --out json 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "cue export failed for '$CuePath'.`n$($output -join [Environment]::NewLine)"
            }
        }
        finally {
            if (Test-Path -LiteralPath $temporaryCuePath) {
                Remove-Item -LiteralPath $temporaryCuePath -Force
            }
        }
    }

    return ($output | ConvertFrom-Json -AsHashtable -Depth 100)
}

function Import-JsonArtifact {
    param(
        [Parameter(Mandatory)]
        [string]$JsonPath
    )

    return (Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100)
}

function Write-ArtifactJson {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Artifact,

        [Parameter(Mandatory)]
        [string]$JsonPath
    )

    $json = $Artifact | ConvertTo-Json -Depth 100
    [System.IO.File]::WriteAllText($JsonPath, ($json.TrimEnd() + [Environment]::NewLine))
}

function Import-SpecTraceArtifactFromPath {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [Parameter(Mandatory)]
        [string]$Path,

        [string]$CueExecutable
    )

    $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    switch ($extension) {
        '.json' {
            return Import-JsonArtifact -JsonPath $Path
        }
        '.cue' {
            if ([string]::IsNullOrWhiteSpace($CueExecutable)) {
                throw "CueExecutable is required to import '$Path'."
            }

            return Export-CueArtifact -RepoRoot $RepoRoot -CuePath $Path -CueExecutable $CueExecutable
        }
        '.md' {
            return New-ArtifactModelFromMarkdown -Path $Path -RepoRoot $RepoRoot
        }
        default {
            throw "Unsupported artifact extension '$extension' for '$Path'."
        }
    }
}

function Get-SectionTitleFromArtifact {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Artifact,

        [Parameter(Mandatory)]
        [string]$SectionKey
    )

    if ($Artifact.Contains('section_titles') -and $Artifact['section_titles'].Contains($SectionKey)) {
        return $Artifact['section_titles'][$SectionKey]
    }

    $words = $SectionKey -split '_'
    return (($words | ForEach-Object {
                if ($_.Length -gt 0) {
                    $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1)
                }
            }) -join ' ')
}

function Convert-TraceValueToMarkdown {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    return $Value
}

function Convert-ToYamlScalar {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    return ($Value | ConvertTo-Json -Compress)
}

function Get-GeneratedMarkdownNotice {
    param(
        [Parameter(Mandatory)]
        [string]$GeneratorComment
    )

    return "<!-- $GeneratorComment -->"
}

function Render-WorkItemFrontMatter {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Artifact
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('---')
    $lines.Add("artifact_id: $(Convert-ToYamlScalar -Value $Artifact['artifact_id'])")
    $lines.Add('artifact_type: "work_item"')
    $lines.Add("title: $(Convert-ToYamlScalar -Value $Artifact['title'])")
    $lines.Add("domain: $(Convert-ToYamlScalar -Value $Artifact['domain'])")
    $lines.Add("status: $(Convert-ToYamlScalar -Value $Artifact['status'])")
    $lines.Add("owner: $(Convert-ToYamlScalar -Value $Artifact['owner'])")

    foreach ($listKey in @('addresses', 'design_links', 'verification_links', 'related_artifacts')) {
        if (-not $Artifact.Contains($listKey)) {
            continue
        }

        $values = @($Artifact[$listKey] | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($values.Count -eq 0) {
            continue
        }

        $lines.Add("${listKey}:")
        foreach ($value in $values) {
            $lines.Add("  - $(Convert-ToYamlScalar -Value $value)")
        }
    }

    $lines.Add('---')
    return ($lines -join "`n")
}

function Convert-StringListToMarkdown {
    param(
        [AllowNull()]
        [object[]]$Items
    )

    $values = @($Items | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace($_.ToString()) })
    if ($values.Count -eq 0) {
        return $null
    }

    return (($values | ForEach-Object { "- $_" }) -join "`n")
}

function Add-MarkdownSection {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList]$Parts,

        [Parameter(Mandatory)]
        [string]$Title,

        [AllowNull()]
        [string]$Content
    )

    if ([string]::IsNullOrWhiteSpace($Content)) {
        return
    }

    $Parts.Add('')
    $Parts.Add("## $Title")
    $Parts.Add('')
    $Parts.Add($Content.Trim())
}

function Get-SupplementalSectionMap {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Artifact
    )

    $sections = [ordered]@{}
    if (-not $Artifact.Contains('supplemental_sections')) {
        return $sections
    }

    foreach ($section in @($Artifact['supplemental_sections'])) {
        if ($null -eq $section -or -not $section.Contains('heading') -or -not $section.Contains('content')) {
            continue
        }

        $heading = $section['heading']
        if ([string]::IsNullOrWhiteSpace($heading) -or $sections.Contains($heading)) {
            continue
        }

        $sections[$heading] = $section['content']
    }

    return $sections
}

function Get-RemainingSupplementalSectionEntries {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Artifact,

        [string[]]$ExcludeHeadings = @()
    )

    if (-not $Artifact.Contains('supplemental_sections')) {
        return @()
    }

    $excluded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($heading in @($ExcludeHeadings)) {
        if (-not [string]::IsNullOrWhiteSpace($heading)) {
            [void]$excluded.Add($heading)
        }
    }

    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($section in @($Artifact['supplemental_sections'])) {
        if ($null -eq $section -or -not $section.Contains('heading') -or -not $section.Contains('content')) {
            continue
        }

        if ($excluded.Contains($section['heading'])) {
            continue
        }

        $entries.Add($section)
    }

    return $entries.ToArray()
}

function Get-RequirementTraceEntriesForRendering {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Trace
    )

    $entries = New-Object System.Collections.Generic.List[object]
    $orderedKeys = @('satisfied_by', 'implemented_by', 'verified_by', 'derived_from', 'supersedes', 'upstream_refs', 'test_refs', 'code_refs', 'x_test_refs', 'x_code_refs', 'related')
    foreach ($key in $orderedKeys) {
        if (-not $Trace.Contains($key)) {
            continue
        }

        $values = @(Get-NonEmptyArray -Value $Trace[$key])
        if ($values.Count -eq 0) {
            continue
        }

        $label = switch ($key) {
            'x_test_refs' { 'Test Refs' }
            'x_code_refs' { 'Code Refs' }
            default { Convert-CueKeyToTraceLabel -Key $key }
        }

        $entries.Add([ordered]@{
                label  = $label
                values = $values
            })
    }

    foreach ($key in $Trace.Keys | Where-Object { $_ -match '^x_[A-Za-z0-9_]+$' -and $_ -notin @('x_test_refs', 'x_code_refs') }) {
        $values = @(Get-NonEmptyArray -Value $Trace[$key])
        if ($values.Count -eq 0) {
            continue
        }

        $label = (($key -replace '^x_', '' -split '_') | ForEach-Object {
                if ($_.Length -gt 0) {
                    $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1)
                }
            }) -join ' '

        $entries.Add([ordered]@{
                label  = $label
                values = $values
            })
    }

    return $entries.ToArray()
}

function Render-PublishedSpecificationArtifactMarkdown {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Artifact,

        [string]$GeneratorComment = 'Generated from sibling .json by scripts/spec-trace/Render-SpecTraceMarkdownFromJson.ps1. Do not edit this file directly.'
    )

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add((Get-GeneratedMarkdownNotice -GeneratorComment $GeneratorComment))
    $parts.Add('')
    $parts.Add("# $($Artifact['artifact_id']) - $($Artifact['title'])")

    foreach ($section in @(
            @{ Title = 'Purpose'; Content = $Artifact['purpose'] },
            @{ Title = 'Scope'; Content = $Artifact['scope'] },
            @{ Title = 'Context'; Content = $Artifact['context'] }
        )) {
        Add-MarkdownSection -Parts $parts -Title $section.Title -Content $section.Content
    }

    $openQuestions = Convert-StringListToMarkdown -Items $Artifact['open_questions']
    Add-MarkdownSection -Parts $parts -Title 'Open Questions' -Content $openQuestions

    foreach ($section in (Get-RemainingSupplementalSectionEntries -Artifact $Artifact -ExcludeHeadings @('Open Questions'))) {
        Add-MarkdownSection -Parts $parts -Title $section['heading'] -Content $section['content']
    }

    foreach ($requirement in @($Artifact['requirements'])) {
        $parts.Add('')
        $parts.Add("## $($requirement['id']) $($requirement['title'])")
        $parts.Add($requirement['statement'])

        if ($requirement.Contains('trace')) {
            $traceEntries = @(Get-RequirementTraceEntriesForRendering -Trace $requirement['trace'])
            if ($traceEntries.Count -gt 0) {
                $parts.Add('')
                $parts.Add('Trace:')
                foreach ($entry in $traceEntries) {
                    $parts.Add("- $($entry['label']):")
                    foreach ($value in @($entry['values'])) {
                        $parts.Add("  - $(Convert-TraceValueToMarkdown -Value $value)")
                    }
                }
            }
        }

        if ($requirement.Contains('notes')) {
            $notes = Convert-StringListToMarkdown -Items $requirement['notes']
            if (-not [string]::IsNullOrWhiteSpace($notes)) {
                $parts.Add('')
                $parts.Add('Notes:')
                $parts.Add($notes)
            }
        }
        elseif ($requirement.Contains('notes_markdown') -and -not [string]::IsNullOrWhiteSpace($requirement['notes_markdown'])) {
            $parts.Add('')
            $parts.Add('Notes:')
            $parts.Add($requirement['notes_markdown'].Trim())
        }
    }

    return (($parts -join "`n").Trim() + "`n")
}

function Render-PublishedArchitectureArtifactMarkdown {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Artifact,

        [string]$GeneratorComment = 'Generated from sibling .json by scripts/spec-trace/Render-SpecTraceMarkdownFromJson.ps1. Do not edit this file directly.'
    )

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add((Get-GeneratedMarkdownNotice -GeneratorComment $GeneratorComment))
    $parts.Add('')
    $parts.Add("# $($Artifact['artifact_id']) - $($Artifact['title'])")

    $supplemental = Get-SupplementalSectionMap -Artifact $Artifact
    Add-MarkdownSection -Parts $parts -Title 'Purpose' -Content $Artifact['purpose']
    Add-MarkdownSection -Parts $parts -Title 'Scope' -Content $supplemental['Scope']

    if ($supplemental.Contains('Requirements Satisfied')) {
        Add-MarkdownSection -Parts $parts -Title 'Requirements Satisfied' -Content $supplemental['Requirements Satisfied']
    }
    else {
        Add-MarkdownSection -Parts $parts -Title 'Requirements Satisfied' -Content (Convert-StringListToMarkdown -Items $Artifact['satisfies'])
    }

    Add-MarkdownSection -Parts $parts -Title 'Design Summary' -Content $Artifact['design_summary']
    Add-MarkdownSection -Parts $parts -Title 'Key Components' -Content (Convert-StringListToMarkdown -Items $Artifact['key_components'])
    Add-MarkdownSection -Parts $parts -Title 'Data and State Considerations' -Content $Artifact['data_and_state_considerations']
    Add-MarkdownSection -Parts $parts -Title 'Edge Cases and Constraints' -Content (Convert-StringListToMarkdown -Items $Artifact['edge_cases_and_constraints'])
    Add-MarkdownSection -Parts $parts -Title 'Alternatives Considered' -Content (Convert-StringListToMarkdown -Items $Artifact['alternatives_considered'])
    Add-MarkdownSection -Parts $parts -Title 'Risks' -Content (Convert-StringListToMarkdown -Items $Artifact['risks'])
    Add-MarkdownSection -Parts $parts -Title 'Open Questions' -Content (Convert-StringListToMarkdown -Items $Artifact['open_questions'])

    foreach ($section in (Get-RemainingSupplementalSectionEntries -Artifact $Artifact -ExcludeHeadings @('Scope', 'Requirements Satisfied'))) {
        Add-MarkdownSection -Parts $parts -Title $section['heading'] -Content $section['content']
    }

    return (($parts -join "`n").Trim() + "`n")
}

function Render-PublishedWorkItemArtifactMarkdown {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Artifact,

        [string]$GeneratorComment = 'Generated from sibling .json by scripts/spec-trace/Render-SpecTraceMarkdownFromJson.ps1. Do not edit this file directly.'
    )

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add((Render-WorkItemFrontMatter -Artifact $Artifact))
    $parts.Add('')
    $parts.Add((Get-GeneratedMarkdownNotice -GeneratorComment $GeneratorComment))
    $parts.Add('')
    $parts.Add("# $($Artifact['artifact_id']) - $($Artifact['title'])")

    $supplemental = Get-SupplementalSectionMap -Artifact $Artifact
    Add-MarkdownSection -Parts $parts -Title 'Summary' -Content $Artifact['summary']

    if ($supplemental.Contains('Requirements Addressed')) {
        Add-MarkdownSection -Parts $parts -Title 'Requirements Addressed' -Content $supplemental['Requirements Addressed']
    }
    else {
        Add-MarkdownSection -Parts $parts -Title 'Requirements Addressed' -Content (Convert-StringListToMarkdown -Items $Artifact['addresses'])
    }

    if ($supplemental.Contains('Design Inputs')) {
        Add-MarkdownSection -Parts $parts -Title 'Design Inputs' -Content $supplemental['Design Inputs']
    }
    else {
        Add-MarkdownSection -Parts $parts -Title 'Design Inputs' -Content (Convert-StringListToMarkdown -Items $Artifact['design_links'])
    }

    Add-MarkdownSection -Parts $parts -Title 'Planned Changes' -Content $Artifact['planned_changes']
    Add-MarkdownSection -Parts $parts -Title 'Out of Scope' -Content (Convert-StringListToMarkdown -Items $Artifact['out_of_scope'])
    Add-MarkdownSection -Parts $parts -Title 'Verification Plan' -Content $Artifact['verification_plan']
    Add-MarkdownSection -Parts $parts -Title 'Completion Notes' -Content $Artifact['completion_notes']

    if ($supplemental.Contains('Trace Links')) {
        Add-MarkdownSection -Parts $parts -Title 'Trace Links' -Content $supplemental['Trace Links']
    }
    else {
        $traceLines = New-Object System.Collections.Generic.List[string]
        $traceLines.Add('Addresses:')
        $traceLines.Add('')
        $traceLines.Add((Convert-StringListToMarkdown -Items $Artifact['addresses']))
        $traceLines.Add('')
        $traceLines.Add('Uses Design:')
        $traceLines.Add('')
        $traceLines.Add((Convert-StringListToMarkdown -Items $Artifact['design_links']))
        $traceLines.Add('')
        $traceLines.Add('Verified By:')
        $traceLines.Add('')
        $traceLines.Add((Convert-StringListToMarkdown -Items $Artifact['verification_links']))
        Add-MarkdownSection -Parts $parts -Title 'Trace Links' -Content (($traceLines -join "`n").Trim())
    }

    foreach ($section in (Get-RemainingSupplementalSectionEntries -Artifact $Artifact -ExcludeHeadings @('Requirements Addressed', 'Design Inputs', 'Trace Links'))) {
        Add-MarkdownSection -Parts $parts -Title $section['heading'] -Content $section['content']
    }

    return (($parts -join "`n").Trim() + "`n")
}

function Render-PublishedVerificationArtifactMarkdown {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Artifact,

        [string]$GeneratorComment = 'Generated from sibling .json by scripts/spec-trace/Render-SpecTraceMarkdownFromJson.ps1. Do not edit this file directly.'
    )

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add((Get-GeneratedMarkdownNotice -GeneratorComment $GeneratorComment))
    $parts.Add('')
    $parts.Add("# $($Artifact['artifact_id']) - $($Artifact['title'])")

    $supplemental = Get-SupplementalSectionMap -Artifact $Artifact
    Add-MarkdownSection -Parts $parts -Title 'Scope' -Content $Artifact['scope']

    if ($supplemental.Contains('Requirements Verified')) {
        Add-MarkdownSection -Parts $parts -Title 'Requirements Verified' -Content $supplemental['Requirements Verified']
    }
    else {
        Add-MarkdownSection -Parts $parts -Title 'Requirements Verified' -Content (Convert-StringListToMarkdown -Items $Artifact['verifies'])
    }

    Add-MarkdownSection -Parts $parts -Title 'Verification Method' -Content $Artifact['verification_method']
    Add-MarkdownSection -Parts $parts -Title 'Preconditions' -Content (Convert-StringListToMarkdown -Items $Artifact['preconditions'])

    if ($supplemental.Contains('Procedure or Approach')) {
        Add-MarkdownSection -Parts $parts -Title 'Procedure or Approach' -Content $supplemental['Procedure or Approach']
    }
    else {
        Add-MarkdownSection -Parts $parts -Title 'Procedure or Approach' -Content (Convert-StringListToMarkdown -Items $Artifact['procedure'])
    }

    Add-MarkdownSection -Parts $parts -Title 'Expected Result' -Content $Artifact['expected_result']

    if ($supplemental.Contains('Evidence')) {
        Add-MarkdownSection -Parts $parts -Title 'Evidence' -Content $supplemental['Evidence']
    }
    else {
        Add-MarkdownSection -Parts $parts -Title 'Evidence' -Content (Convert-StringListToMarkdown -Items $Artifact['evidence'])
    }

    if ($supplemental.Contains('Status')) {
        Add-MarkdownSection -Parts $parts -Title 'Status' -Content $supplemental['Status']
    }
    else {
        if ($Artifact.Contains('status_summary')) {
            Add-MarkdownSection -Parts $parts -Title 'Status' -Content $Artifact['status_summary']
        }
        else {
            Add-MarkdownSection -Parts $parts -Title 'Status' -Content $Artifact['status']
        }
    }

    if ($supplemental.Contains('Related Artifacts')) {
        Add-MarkdownSection -Parts $parts -Title 'Related Artifacts' -Content $supplemental['Related Artifacts']
    }
    else {
        Add-MarkdownSection -Parts $parts -Title 'Related Artifacts' -Content (Convert-StringListToMarkdown -Items $Artifact['related_artifacts'])
    }

    foreach ($section in (Get-RemainingSupplementalSectionEntries -Artifact $Artifact -ExcludeHeadings @('Requirements Verified', 'Procedure or Approach', 'Evidence', 'Status', 'Related Artifacts'))) {
        Add-MarkdownSection -Parts $parts -Title $section['heading'] -Content $section['content']
    }

    return (($parts -join "`n").Trim() + "`n")
}

function Render-SpecificationArtifactMarkdown {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Artifact,

        [string]$GeneratorComment = 'Generated from sibling .json by scripts/spec-trace/Render-SpecTraceMarkdownFromJson.ps1. Do not edit this file directly.'
    )

    if (-not $Artifact.Contains('section_order')) {
        return Render-PublishedSpecificationArtifactMarkdown -Artifact $Artifact -GeneratorComment $GeneratorComment
    }

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add((Get-GeneratedMarkdownNotice -GeneratorComment $GeneratorComment))
    $parts.Add('')
    $parts.Add("# $($Artifact['artifact_id']) - $($Artifact['title'])")

    foreach ($sectionKey in @($Artifact['section_order'])) {
        $title = Get-SectionTitleFromArtifact -Artifact $Artifact -SectionKey $sectionKey
        $content = $Artifact['sections'][$sectionKey]
        if ([string]::IsNullOrWhiteSpace($content)) {
            continue
        }

        $parts.Add('')
        $parts.Add("## $title")
        $parts.Add('')
        $parts.Add($content.Trim())
    }

    foreach ($requirement in @($Artifact['requirements'])) {
        $parts.Add('')
        $parts.Add("## $($requirement['id']) $($requirement['title'])")
        $parts.Add($requirement['statement'])

        if ($requirement.Contains('trace')) {
            $parts.Add('')
            $parts.Add('Trace:')
            foreach ($entry in (Get-RequirementTraceEntriesForRendering -Trace $requirement['trace'])) {
                $parts.Add("- $($entry['label']):")
                foreach ($value in @($entry['values'])) {
                    $parts.Add("  - $(Convert-TraceValueToMarkdown -Value $value)")
                }
            }
        }

        if ($requirement.Contains('notes_markdown') -and -not [string]::IsNullOrWhiteSpace($requirement['notes_markdown'])) {
            $parts.Add('')
            $parts.Add('Notes:')
            $parts.Add($requirement['notes_markdown'].Trim())
        }
    }

    return (($parts -join "`n").Trim() + "`n")
}

function Render-GenericArtifactMarkdown {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Artifact,

        [string]$GeneratorComment = 'Generated from sibling .json by scripts/spec-trace/Render-SpecTraceMarkdownFromJson.ps1. Do not edit this file directly.'
    )

    if (-not $Artifact.Contains('section_order')) {
        switch ($Artifact['artifact_type']) {
            'architecture' { return Render-PublishedArchitectureArtifactMarkdown -Artifact $Artifact -GeneratorComment $GeneratorComment }
            'work_item' { return Render-PublishedWorkItemArtifactMarkdown -Artifact $Artifact -GeneratorComment $GeneratorComment }
            'verification' { return Render-PublishedVerificationArtifactMarkdown -Artifact $Artifact -GeneratorComment $GeneratorComment }
        }
    }

    $parts = New-Object System.Collections.Generic.List[string]
    if ($Artifact['artifact_type'] -eq 'work_item') {
        $parts.Add((Render-WorkItemFrontMatter -Artifact $Artifact))
        $parts.Add('')
    }

    $parts.Add((Get-GeneratedMarkdownNotice -GeneratorComment $GeneratorComment))
    $parts.Add('')
    $parts.Add("# $($Artifact['artifact_id']) - $($Artifact['title'])")

    foreach ($sectionKey in @($Artifact['section_order'])) {
        $title = Get-SectionTitleFromArtifact -Artifact $Artifact -SectionKey $sectionKey
        $content = $Artifact['sections'][$sectionKey]
        if ([string]::IsNullOrWhiteSpace($content)) {
            continue
        }

        $parts.Add('')
        $parts.Add("## $title")
        $parts.Add('')
        $parts.Add($content.Trim())
    }

    return (($parts -join "`n").Trim() + "`n")
}

function Render-ArtifactMarkdown {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Artifact,

        [string]$GeneratorComment = 'Generated from sibling .json by scripts/spec-trace/Render-SpecTraceMarkdownFromJson.ps1. Do not edit this file directly.'
    )

    if ($Artifact['artifact_type'] -eq 'specification') {
        return Render-SpecificationArtifactMarkdown -Artifact $Artifact -GeneratorComment $GeneratorComment
    }

    return Render-GenericArtifactMarkdown -Artifact $Artifact -GeneratorComment $GeneratorComment
}

function New-ArtifactSnapshot {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Artifact,

        [Parameter(Mandatory)]
        [string]$RepoRelativePath
    )

    $snapshot = [ordered]@{
        path          = $RepoRelativePath
        artifact_id   = $Artifact['artifact_id']
        artifact_type = $Artifact['artifact_type']
        title         = $Artifact['title']
        domain        = $Artifact['domain']
        status        = $Artifact['status']
        owner         = $Artifact['owner']
    }

    foreach ($key in $Artifact.Keys) {
        if ($key -in @('artifact_id', 'artifact_type', 'title', 'domain', 'status', 'owner')) {
            continue
        }

        $snapshot[$key] = $Artifact[$key]
    }

    return $snapshot
}

function New-ComparableArtifactSnapshot {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Artifact,

        [Parameter(Mandatory)]
        [string]$RepoRelativePath,

        [string]$SchemaUri = 'https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json'
    )

    $publishedArtifact = Convert-LegacyArtifactToPublishedSchema -Artifact $Artifact -SchemaUri $SchemaUri
    return New-ArtifactSnapshot -Artifact $publishedArtifact -RepoRelativePath $RepoRelativePath
}

function Get-ComparableArtifactString {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    return $Value.Replace("`r`n", "`n").Replace("`r", "`n").TrimEnd()
}

function Format-ArtifactValuePreview {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return '<null>'
    }

    $preview = if ($Value -is [string]) {
        Get-ComparableArtifactString -Value $Value
    }
    else {
        $Value | ConvertTo-Json -Compress -Depth 20
    }

    if ($preview.Length -gt 160) {
        return $preview.Substring(0, 157) + '...'
    }

    return $preview
}

function Compare-ArtifactValues {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [AllowNull()]
        [object]$Expected,

        [AllowNull()]
        [object]$Actual
    )

    $mismatches = New-Object System.Collections.Generic.List[string]

    if ($null -eq $Expected -and $null -eq $Actual) {
        return @()
    }

    if ($null -eq $Expected -or $null -eq $Actual) {
        $mismatches.Add("value mismatch at '$Path': expected $(Format-ArtifactValuePreview -Value $Expected) but found $(Format-ArtifactValuePreview -Value $Actual).")
        return $mismatches.ToArray()
    }

    $expectedIsDictionary = $Expected -is [System.Collections.IDictionary]
    $actualIsDictionary = $Actual -is [System.Collections.IDictionary]
    if ($expectedIsDictionary -or $actualIsDictionary) {
        if (-not ($expectedIsDictionary -and $actualIsDictionary)) {
            $mismatches.Add("type mismatch at '$Path': expected $(Format-ArtifactValuePreview -Value $Expected) but found $(Format-ArtifactValuePreview -Value $Actual).")
            return $mismatches.ToArray()
        }

        $expectedKeys = @($Expected.Keys | ForEach-Object { $_.ToString() } | Sort-Object)
        $actualKeys = @($Actual.Keys | ForEach-Object { $_.ToString() } | Sort-Object)
        foreach ($key in $expectedKeys) {
            if ($actualKeys -notcontains $key) {
                $mismatches.Add("missing key at '$Path.$key'.")
            }
        }
        foreach ($key in $actualKeys) {
            if ($expectedKeys -notcontains $key) {
                $mismatches.Add("unexpected key at '$Path.$key'.")
            }
        }
        foreach ($key in $expectedKeys) {
            if ($actualKeys -contains $key) {
                foreach ($mismatch in (Compare-ArtifactValues -Path "$Path.$key" -Expected $Expected[$key] -Actual $Actual[$key])) {
                    $mismatches.Add($mismatch)
                }
            }
        }

        return $mismatches.ToArray()
    }

    $expectedIsEnumerable = $Expected -is [System.Collections.IEnumerable] -and -not ($Expected -is [string])
    $actualIsEnumerable = $Actual -is [System.Collections.IEnumerable] -and -not ($Actual -is [string])
    if ($expectedIsEnumerable -or $actualIsEnumerable) {
        if (-not ($expectedIsEnumerable -and $actualIsEnumerable)) {
            $mismatches.Add("type mismatch at '$Path': expected $(Format-ArtifactValuePreview -Value $Expected) but found $(Format-ArtifactValuePreview -Value $Actual).")
            return $mismatches.ToArray()
        }

        $expectedItems = @($Expected)
        $actualItems = @($Actual)
        if ($expectedItems.Count -ne $actualItems.Count) {
            $mismatches.Add("length mismatch at '$Path': expected $($expectedItems.Count) item(s) but found $($actualItems.Count).")
        }

        $maxCount = [Math]::Max($expectedItems.Count, $actualItems.Count)
        for ($index = 0; $index -lt $maxCount; $index++) {
            if ($index -ge $expectedItems.Count) {
                $mismatches.Add("unexpected item at '$Path[$index]': $(Format-ArtifactValuePreview -Value $actualItems[$index]).")
                continue
            }

            if ($index -ge $actualItems.Count) {
                $mismatches.Add("missing item at '$Path[$index]': expected $(Format-ArtifactValuePreview -Value $expectedItems[$index]).")
                continue
            }

            foreach ($mismatch in (Compare-ArtifactValues -Path "$Path[$index]" -Expected $expectedItems[$index] -Actual $actualItems[$index])) {
                $mismatches.Add($mismatch)
            }
        }

        return $mismatches.ToArray()
    }

    if ($Expected -is [string] -or $Actual -is [string]) {
        if (-not ($Expected -is [string] -and $Actual -is [string])) {
            $mismatches.Add("type mismatch at '$Path': expected $(Format-ArtifactValuePreview -Value $Expected) but found $(Format-ArtifactValuePreview -Value $Actual).")
            return $mismatches.ToArray()
        }

        $expectedText = Get-ComparableArtifactString -Value $Expected
        $actualText = Get-ComparableArtifactString -Value $Actual
        if ($expectedText -cne $actualText) {
            $mismatches.Add("value mismatch at '$Path': expected $(Format-ArtifactValuePreview -Value $Expected) but found $(Format-ArtifactValuePreview -Value $Actual).")
        }

        return $mismatches.ToArray()
    }

    if ($Expected -cne $Actual) {
        $mismatches.Add("value mismatch at '$Path': expected $(Format-ArtifactValuePreview -Value $Expected) but found $(Format-ArtifactValuePreview -Value $Actual).")
    }

    return $mismatches.ToArray()
}

function Compare-ArtifactSnapshots {
    param(
        [Parameter(Mandatory)]
        [object]$Expected,

        [Parameter(Mandatory)]
        [object]$Actual
    )

    $path = if ($Expected -is [System.Collections.IDictionary] -and $Expected.Contains('path')) {
        $Expected['path']
    }
    else {
        'artifact'
    }

    return @(Compare-ArtifactValues -Path $path -Expected $Expected -Actual $Actual)
}
