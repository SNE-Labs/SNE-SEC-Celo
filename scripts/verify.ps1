$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvPython = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$pythonCommand = if (Test-Path -LiteralPath $venvPython) { $venvPython } else { "python" }

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Gate failed with exit code ${LASTEXITCODE}: $Command $Arguments"
    }
}

Push-Location $repositoryRoot
try {
    $env:PYTHONPATH = "src"
    Invoke-Checked $pythonCommand -m unittest discover -s tests -v
    Invoke-Checked $pythonCommand -m ruff check .
    Invoke-Checked $pythonCommand -m mypy src
    Invoke-Checked git diff --check
}
finally {
    Pop-Location
}
