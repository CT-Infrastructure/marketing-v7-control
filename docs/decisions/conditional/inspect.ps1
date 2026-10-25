# Limited offline data inspection; does not replace validate.py or independent tests.
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$register = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'register.json') | ConvertFrom-Json
$policy = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'policy.json') | ConvertFrom-Json
$graph = Get-Content -Raw -LiteralPath (Join-Path $root 'orchestration/task_graph.json') | ConvertFrom-Json
$tasks = @($graph.tasks | Where-Object kind -eq selection)
if ($register.decisions.Count -ne 40 -or $tasks.Count -ne 40) { throw 'Count mismatch' }
if (@($register.decisions.task_key | Sort-Object -Unique).Count -ne 40) { throw 'Duplicate key' }
if (Compare-Object @($register.decisions.task_key) @($tasks.key)) { throw 'Selection coverage mismatch' }
if ($policy.default_decision -ne 'DEFERRED' -or $policy.production_authorized -ne $false) { throw 'Policy promotion' }
foreach ($record in $register.decisions) {
    $cells = $record.evidence[1].source_row.Trim('|').Split('|') | ForEach-Object { $_.Trim() }
    if (-not $cells[0].Contains($record.name)) { throw "Row identity: $($record.task_key)" }
    if ($record.decision -ne 'DEFERRED') { throw "Decision: $($record.task_key)" }
    foreach ($flag in @('selected', 'installed', 'enabled', 'production_authorized')) {
        if ($record.$flag -cne $false) { throw "Effect flag: $($record.task_key)/$flag" }
    }
    $actualHash = (Get-FileHash -LiteralPath (Join-Path $root $record.evidence[0].path) -Algorithm SHA256).Hash.ToLower()
    if ($actualHash -ne $record.evidence[0].sha256) { throw "Issue hash: $($record.task_key)" }
}
foreach ($source in $register.sources) {
    $actualHash = (Get-FileHash -LiteralPath (Join-Path $root $source.path) -Algorithm SHA256).Hash.ToLower()
    if ($actualHash -ne $source.sha256) { throw "Source hash: $($source.path)" }
}
Write-Output 'PASS: limited data inspection; 40 deferred records and source hashes. Python tests NOT_RUN.'
