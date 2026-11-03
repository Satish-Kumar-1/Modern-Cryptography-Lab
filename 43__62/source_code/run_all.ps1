$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path logs | Out-Null
$experiments = @('exp1_normal_exchange','exp2_mitm_attack','exp3_authenticated_exchange','exp4_tamper_test','exp5_hkdf_analysis','exp6_error_handling')
foreach ($name in $experiments) {
    Write-Host "Running $name"
    python "$name.py" 2>&1 | Tee-Object -FilePath "logs/$name.txt"
    if ($LASTEXITCODE -ne 0) { throw "$name failed" }
}
Write-Host 'All six experiments completed. Logs are in logs/.'
