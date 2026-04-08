param(
    [string]$RpcBind = "127.0.0.1:18080",
    [string]$SerialPort = "COM4",
    [string]$Wallet = "0x5dd14204a9b64cc6b4e06b5b5089482e6e1f1ea8",
    [int]$ChainId = 11155111
)

$ErrorActionPreference = "Stop"

$repoRoot = "C:\Github\mesh"
$exePath = Join-Path $repoRoot "target\x86_64-pc-windows-gnu\debug\relayer.exe"

if (-not (Test-Path $exePath)) {
    throw "relayer.exe not found: $exePath"
}

Get-Process relayer -ErrorAction SilentlyContinue | Stop-Process -Force

$stdout = Join-Path $repoRoot "relayer-run.log"
$stderr = Join-Path $repoRoot "relayer-run.err"
Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue

$cmd = @(
    "set EOA_ADDRESS=$Wallet"
    "set SERIAL_PORT=$SerialPort"
    "set BIND_ADDR=$RpcBind"
    "set CHAIN_ID=$ChainId"
    "set RUST_LOG=info"
    $exePath
) -join "&& "

$proc = Start-Process -FilePath "cmd.exe" `
    -ArgumentList "/c", $cmd `
    -WorkingDirectory $repoRoot `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -PassThru

Start-Sleep -Seconds 4

if (-not (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)) {
    $errText = ""
    if (Test-Path $stderr) {
        $errText = Get-Content $stderr -Raw
    }
    throw "relayer failed to start.`n$errText"
}

$url = "http://$RpcBind/"
$body = '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
$response = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Body $body

Write-Host "relayer_pid=$($proc.Id)"
Write-Host "rpc_url=$url"
Write-Host "eth_chainId_result=$($response.result)"
Write-Host "expected_chain_id=0x$('{0:x}' -f $ChainId)"

if ($response.result -ne ("0x{0:x}" -f $ChainId)) {
    throw "Chain ID mismatch from relayer."
}

Write-Host "Relayer is ready for MetaMask."
