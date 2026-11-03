# Windows PowerShell version of run_all.sh
# Reproduces everything from scratch: new keys, signature, all experiments, tests.
# Run from the project folder:   .\run_all.ps1
# If PowerShell blocks scripts, run once:  Set-ExecutionPolicy -Scope Process Bypass
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not $env:SIGN_PASSPHRASE) { $env:SIGN_PASSPHRASE = "demo-passphrase-not-a-real-secret" }
$KeyDir = Join-Path $env:USERPROFILE "project4_private_keys"
New-Item -ItemType Directory -Force -Path logs | Out-Null

python sign_verify.py keygen --name author --key-dir $KeyDir --pub-dir sample | Tee-Object -FilePath logs/01_keygen.txt
python sign_verify.py sign --key "$KeyDir\author_private.pem" --doc sample/document.txt --sig sample/document.sig | Tee-Object -FilePath logs/02_sign.txt
python experiments.py
python key_substitution_demo.py
python -m pytest -q | Tee-Object -FilePath logs/11_pytest.txt