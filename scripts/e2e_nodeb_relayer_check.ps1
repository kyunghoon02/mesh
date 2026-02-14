param(
    [string]$RpcUrl = "http://localhost:8080",
    [int]$StatusRepeat = 5,
    [int]$StatusIntervalMs = 500,
    [string]$ChainId = "",
    [switch]$SkipNodeB = $true,
    [switch]$StrictNodeB = $false,
    [switch]$UseSendTransaction = $false,
    [switch]$RunSignRequest = $false,
    [string]$OutputJson = ""
)

$global:NextId = 1
$global:Passed = 0
$global:Warning = 0
$global:Failed = 0

function Invoke-MeshRpc {
    param(
        [Parameter(Mandatory)] [string]$Method,
        [Parameter()] [object[]]$Params = @()
    )

    $id = $global:NextId
    $global:NextId += 1

    $body = @{
        jsonrpc = "2.0"
        id = $id
        method = $Method
        params = $Params
    } | ConvertTo-Json -Depth 10

    try {
        $resp = Invoke-RestMethod -Uri $RpcUrl -Method Post -Body $body -ContentType "application/json"
        [PSCustomObject]@{
            id = $id
            request = $Method
            ok = ($null -eq $resp.error)
            response = $resp
            details = $null
        }
    }
    catch {
        $message = $_.Exception.Message
        [PSCustomObject]@{
            id = $id
            request = $Method
            ok = $false
            response = @{ error = @{ message = $message } }
            details = $message
        }
    }
}

function Write-CheckLine {
    param(
        [string]$Message,
        [ValidateSet("OK", "WARN", "FAIL")]
        [string]$Level,
        [string]$Detail = ""
    )

    switch ($Level) {
        "OK" {
            $global:Passed += 1
            Write-Host "[OK]  $Message" -ForegroundColor Green
        }
        "WARN" {
            $global:Warning += 1
            Write-Host "[WARN] $Message" -ForegroundColor Yellow
        }
        "FAIL" {
            $global:Failed += 1
            Write-Host "[FAIL] $Message" -ForegroundColor Red
        }
    }

    if ($Detail) {
        Write-Host "       $Detail" -ForegroundColor DarkGray
    }
}

function IsExpectedSerialMissing($message) {
    return ($message -match 'SERIAL_PORT not configured' -or $message -match 'No such device' -or $message -match 'No such file or directory')
}

# --- Step 1: mesh_getStatus ---
if ($SkipNodeB) {
    Write-Host "[1/4] mesh_getStatus (Node B 미연결 허용 모드)" -ForegroundColor Cyan
} else {
    Write-Host "[1/4] mesh_getStatus" -ForegroundColor Cyan
}

for ($i = 1; $i -le $StatusRepeat; $i++) {
    $result = Invoke-MeshRpc -Method 'mesh_getStatus'

    if ($result.ok) {
        $status = $result.response.result
        Write-CheckLine -Level OK -Message "mesh_getStatus #${i}: status=$status"
    } else {
        $reason = if ($result.response.error.message) { $result.response.error.message } else { 'unknown' }
        if ($SkipNodeB -and (IsExpectedSerialMissing($reason))) {
            Write-CheckLine -Level WARN -Message "mesh_getStatus #${i}: Node B 미연결(예상)" -Detail $reason
        } else {
            Write-CheckLine -Level FAIL -Message "mesh_getStatus #$i 실패" -Detail $reason
            if ($StrictNodeB) { exit 1 }
        }
    }

    Start-Sleep -Milliseconds $StatusIntervalMs
}

# --- Step 2: chain_id ---
Write-Host "[2/4] chain_id 확인" -ForegroundColor Cyan
$chainResp = Invoke-MeshRpc -Method 'eth_chainId'
if (-not $chainResp.ok) {
    $reason = if ($chainResp.response.error.message) { $chainResp.response.error.message } else { 'unknown' }
    if ($SkipNodeB -and ($reason -match 'UPSTREAM_RPC not configured' -or $reason -match 'Unsupported method')) {
        Write-CheckLine -Level WARN -Message "eth_chainId 실패(예상)" -Detail $reason
    } else {
        Write-CheckLine -Level FAIL -Message "eth_chainId 실패" -Detail $reason
        exit 1
    }
    $chain = $null
} else {
    Write-CheckLine -Level OK -Message "eth_chainId=$($chainResp.response.result)"
    $chain = $chainResp.response.result
}

if (-not $chain -and $ChainId) {
    $chain = $ChainId
}

# --- Step 3: mesh_getChainConfig ---
Write-Host "[3/4] 체인 설정 조회(mesh_getChainConfig)" -ForegroundColor Cyan
if ($chain) {
    $cfgResp = Invoke-MeshRpc -Method 'mesh_getChainConfig' -Params @(@{ chain_id = $chain })
    if ($cfgResp.ok) {
        Write-CheckLine -Level OK -Message "mesh_getChainConfig OK"
        $cfgResp.response.result | ConvertTo-Json
    } else {
        $reason = if ($cfgResp.response.error.message) { $cfgResp.response.error.message } else { 'unknown' }
        Write-CheckLine -Level WARN -Message "mesh_getChainConfig 실패" -Detail $reason
    }
} else {
    Write-CheckLine -Level WARN -Message "chain_id를 알 수 없어 mesh_getChainConfig 생략"
}

# --- Step 4: tx dry-run 또는 sign dry-run ---
if ($UseSendTransaction) {
    Write-Host "[4/4] 서명 요청 dry-run (eth_sendTransaction)" -ForegroundColor Cyan
    $sendMethod = 'eth_sendTransaction'
    $params = @(@{
            from = "0x0000000000000000000000000000000000000000"
            to = "0x0000000000000000000000000000000000000000"
            value = "0x0"
            data = "0x"
        })
} else {
    Write-Host "[4/4] 트랜잭션 dry-run (eth_call)" -ForegroundColor Cyan
    $sendMethod = 'eth_call'
    $params = @(@{
            to = "0x0000000000000000000000000000000000000000"
            data = "0x"
        }, "latest")
}

$sendResp = Invoke-MeshRpc -Method $sendMethod -Params $params
if ($sendResp.ok) {
    Write-CheckLine -Level OK -Message ("{0} 응답 수신" -f $sendMethod) -Detail ("result={0}" -f $sendResp.response.result)
} else {
    $err = if ($sendResp.response.error) { $sendResp.response.error.message } else { 'unknown' }
    Write-CheckLine -Level WARN -Message ("{0} 응답" -f $sendMethod) -Detail $err
}

# --- Optional Step 5: signature dry-run ---
if ($RunSignRequest) {
    Write-Host "[5/5] 서명 dry-run (wallet 없음 모드)" -ForegroundColor Cyan
    $signResp = Invoke-MeshRpc -Method 'eth_sign' -Params @(
        "0x0000000000000000000000000000000000000000",
        "0x00"
    )
    if ($signResp.ok) {
        Write-CheckLine -Level OK -Message "Sign dry-run 응답 수신"
    } else {
        $err = if ($signResp.response.error) { $signResp.response.error.message } else { 'unknown' }
        Write-CheckLine -Level WARN -Message "Sign dry-run 응답" -Detail $err
    }
}

Write-Host ""
Write-Host "E2E 테스트 체크포인트" -ForegroundColor Cyan
Write-Host "1) Node B Serial 로그에 GET_STATUS 요청 시퀀스가 1씩 증가하는지 확인"
Write-Host "2) SignRequest 전송 시 Node B 로그에서 SignRequest 수신/포워딩이 보이는지 확인"
Write-Host "3) Node A UI에서 서명/거절 화면 진입 확인"
Write-Host "4) Node B 로그에서 Node A 응답 수신 후 serial 응답 반환 확인"
Write-Host ("요약: OK={0}, WARN={1}, FAIL={2}" -f $global:Passed, $global:Warning, $global:Failed)

if ($OutputJson) {
    $summary = [PSCustomObject]@{
        ok = ($global:Failed -eq 0)
        passed = $global:Passed
        warning = $global:Warning
        failed = $global:Failed
        chain = $chain
        skip_node_b = [bool]$SkipNodeB
        run = (Get-Date).ToString("o")
    }
    $summary | ConvertTo-Json | Out-File -FilePath $OutputJson -Encoding utf8
}

if ($global:Failed -gt 0 -and (-not $SkipNodeB -or $StrictNodeB)) {
    exit 1
}

