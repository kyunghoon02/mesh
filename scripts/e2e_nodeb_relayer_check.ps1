param(
    [string]$RpcUrl = "http://localhost:8080",
    [int]$StatusRepeat = 5,
    [int]$StatusIntervalMs = 500,
    [string]$ChainId = "",
    [switch]$SkipNodeB = $true,
    [switch]$StrictNodeB = $false,
    [switch]$UseSendTransaction = $false
)

$global:nextId = 1

function Invoke-MeshRpc {
    param(
        [Parameter(Mandatory)] [string]$Method,
        [Parameter()] [object[]]$Params = @()
    )

    $id = $global:nextId
    $global:nextId += 1

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

if ($SkipNodeB) {
    Write-Host "[1/4] mesh_getStatus (Node B 미연결 허용 모드)" -ForegroundColor Cyan
    for ($i = 1; $i -le $StatusRepeat; $i++) {
        $result = Invoke-MeshRpc -Method 'mesh_getStatus'
        if ($result.ok) {
            $status = $result.response.result
            Write-Host ("mesh_getStatus #{0}: status={1} (실제 연결됨)" -f $i, $status) -ForegroundColor Green
        } else {
            $reason = if ($result.response.error.message) { $result.response.error.message } else { 'unknown' }
            if ($reason -match 'SERIAL_PORT not configured' -or $reason -match 'No such device' -or $reason -match 'No such file or directory') {
                Write-Host ("mesh_getStatus #{0}: Node B 미연결 경고(예상) -> {1}" -f $i, $reason) -ForegroundColor Yellow
            } else {
                Write-Host ("mesh_getStatus #{0} 실패: {1}" -f $i, $reason) -ForegroundColor Red
                if ($StrictNodeB) { exit 1 }
            }
        }
        Start-Sleep -Milliseconds $StatusIntervalMs
    }
}
else {
    Write-Host "[1/4] mesh_getStatus" -ForegroundColor Cyan
    for ($i = 1; $i -le $StatusRepeat; $i++) {
        $result = Invoke-MeshRpc -Method 'mesh_getStatus'
        if ($result.ok) {
            $status = $result.response.result
            Write-Host ("mesh_getStatus #{0}: status={1}" -f $i, $status) -ForegroundColor Green
        } else {
            $reason = if ($result.response.error.message) { $result.response.error.message } else { 'unknown' }
            Write-Host ("mesh_getStatus #{0} 실패: {1}" -f $i, $reason) -ForegroundColor Red
            if ($StrictNodeB) { exit 1 }
        }
        Start-Sleep -Milliseconds $StatusIntervalMs
    }
}

Write-Host "[2/4] chain_id 확인" -ForegroundColor Cyan
$chainResp = Invoke-MeshRpc -Method 'eth_chainId'
if (-not $chainResp.ok) {
    $reason = if ($chainResp.response.error.message) { $chainResp.response.error.message } else { 'unknown' }
    if ($SkipNodeB -and ($reason -match 'UPSTREAM_RPC not configured' -or $ChainId)) {
        Write-Host ("eth_chainId 실패(예상): {0}" -f $reason) -ForegroundColor Yellow
    } else {
        Write-Host ("eth_chainId 실패: {0}" -f $reason) -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host ("eth_chainId={0}" -f $chainResp.response.result) -ForegroundColor Green
    $chain = $chainResp.response.result
}

if (-not $chain -and $ChainId) {
    $chain = $ChainId
}

Write-Host "[3/4] 체인 설정 조회(mesh_getChainConfig)" -ForegroundColor Cyan
if ($chain) {
    $cfgResp = Invoke-MeshRpc -Method 'mesh_getChainConfig' -Params @(@{ chain_id = $chain })
    if ($cfgResp.ok) {
        Write-Host "mesh_getChainConfig OK" -ForegroundColor Green
        $cfgResp.response.result | ConvertTo-Json
    } elseif ($SkipNodeB) {
        $reason = if ($cfgResp.response.error.message) { $cfgResp.response.error.message } else { 'unknown' }
        Write-Host ("mesh_getChainConfig 실패: {0}" -f $reason) -ForegroundColor Yellow
    } else {
        $reason = if ($cfgResp.response.error.message) { $cfgResp.response.error.message } else { 'unknown' }
        Write-Host ("mesh_getChainConfig 실패: {0}" -f $reason) -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "chain_id를 알 수 없어 mesh_getChainConfig 생략" -ForegroundColor Yellow
}

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
if ($sendResp.ok -and $null -eq $sendResp.response.error) {
    Write-Host ("{0}가 relayer를 통과했습니다. 응답: {1}" -f $sendMethod, $sendResp.response.result) -ForegroundColor Green
} else {
    $err = if ($sendResp.response.error) { $sendResp.response.error.message } else { 'unknown' }
    Write-Host ("{0} 응답: {1}" -f $sendMethod, $err) -ForegroundColor Yellow
}

Write-Host "E2E 테스트 체크포인트"
Write-Host "1) Node B Serial 로그에 GET_STATUS 요청 시퀀스가 1씩 증가하는지 확인"
Write-Host "2) SignRequest 전송 시 Node B 로그에서 SignRequest 수신/포워딩이 보이는지 확인"
Write-Host "3) Node A UI에서 서명/거절 화면 진입 확인"
Write-Host "4) Node B 로그에서 Node A 응답 수신 후 serial 응답 반환 확인"
