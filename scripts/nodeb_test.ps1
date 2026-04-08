param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('wallet', 'status', 'enter-pairing', 'pair', 'peer', 'sign-demo')]
    [string]$Command,

    [string]$Port = 'COM4',
    [string]$NodeAPort = 'COM3',
    [int]$Baud = 115200,
    [string]$NodeAMac = 'F0:F5:BD:44:8D:60',
    [string]$Wallet,
    [string]$To = '0x1111111111111111111111111111111111111111',
    [UInt64]$ChainId = 11155111,
    [UInt64]$ValueWei = 0,
    [byte]$Risk = 0,
    [string]$Summary = 'Mesh demo transfer',
    [string]$Distro = 'Ubuntu-24.04'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$repoRootLinux = '/mnt/c/Github/mesh'
$walletCachePath = Join-Path $repoRoot '.nodea_wallet.txt'
$walletDumpPath = Join-Path $env:TEMP 'mesh_nodea_mesh_key.bin'
$NodeBResponseMinLength = 248
$NodeBResponseMaxLength = 250
$NodeBReadTimeoutMs = 65000

function Invoke-Codec {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CodecArgs,
        [switch]$Quiet
    )

    $cmd = "source ~/.cargo/env && cd $repoRootLinux/relayer && cargo run --quiet --bin nodeb_codec -- $CodecArgs"
    if ($Quiet) {
        $result = & wsl.exe -d $Distro bash -lc $cmd 2>$null
    }
    else {
        $result = & wsl.exe -d $Distro bash -lc $cmd
    }
    if ($LASTEXITCODE -ne 0) {
        throw "nodeb_codec failed: $CodecArgs"
    }
    ($result | Out-String).Trim()
}

function Convert-HexToBytes {
    param([string]$Hex)
    $clean = $Hex.Trim()
    if ($clean.StartsWith('0x')) { $clean = $clean.Substring(2) }
    if (($clean.Length % 2) -ne 0) { throw "Invalid hex length" }
    $bytes = New-Object byte[] ($clean.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
    }
    $bytes
}

function Convert-BytesToHex {
    param([byte[]]$Bytes)
    -join ($Bytes | ForEach-Object { $_.ToString('x2') })
}

function Repair-ShiftedResponseBytes {
    param([byte[]]$Bytes)

    if ($Bytes.Length -lt 4) {
        return $null
    }

    if ($Bytes[0] -ne 0xF8 -or $Bytes[1] -ne 0x00 -or $Bytes[2] -ne 0x00) {
        return $null
    }

    $repaired = New-Object byte[] $Bytes.Length
    $repaired[0] = $Bytes[0]
    $repaired[1] = $Bytes[1]
    [Array]::Copy($Bytes, 3, $repaired, 2, $Bytes.Length - 3)
    $repaired[$Bytes.Length - 1] = 0x00
    $repaired
}

function Get-PrintableAsciiRuns {
    param([byte[]]$Bytes)

    $runs = @()
    $current = New-Object System.Collections.Generic.List[byte]
    foreach ($value in $Bytes) {
        if (($value -ge 0x30 -and $value -le 0x39) -or ($value -ge 0x41 -and $value -le 0x5A) -or $value -eq 0x5F) {
            $current.Add($value)
            continue
        }

        if ($current.Count -ge 4) {
            $runs += ,([System.Text.Encoding]::ASCII.GetString($current.ToArray()))
        }
        $current.Clear()
    }

    if ($current.Count -ge 4) {
        $runs += ,([System.Text.Encoding]::ASCII.GetString($current.ToArray()))
    }

    $runs
}

function Try-DecodeResponse {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$ResponseBytes,
        [string]$DecodeWallet
    )

    $variants = New-Object System.Collections.Generic.List[byte[]]
    $variants.Add($ResponseBytes)

    $repaired = Repair-ShiftedResponseBytes $ResponseBytes
    if ($repaired) {
        $variants.Add($repaired)
    }

    foreach ($variant in $variants) {
        $variantHex = Convert-BytesToHex $variant
        try {
            if ($DecodeWallet) {
                return (Invoke-Codec "decode --hex $variantHex --wallet $DecodeWallet" -Quiet)
            }

            return (Invoke-Codec "decode --hex $variantHex" -Quiet)
        }
        catch {
            continue
        }
    }

    $asciiRuns = Get-PrintableAsciiRuns $ResponseBytes
    foreach ($run in $asciiRuns) {
        if ($run -match '^(PAIRING_(SEND|WAIT)_ERR_[A-Z_]+|PAIRING_ERR_[A-Z_]+|PAIRING_PROMPTED|PAIRED|FORWARDED|PAIRING_MODE)$') {
            return "success=true`npayload_text=$run"
        }
    }

    if ($ResponseBytes.Length -ge 10 -and $ResponseBytes[0] -eq 0xF8 -and $ResponseBytes[1] -eq 0x00) {
        $errorCodeIndex = 8
        if ($ResponseBytes.Length -gt $errorCodeIndex) {
            $errorCode = $ResponseBytes[$errorCodeIndex]
            if ($errorCode -ge 1 -and $errorCode -le 6) {
                $errorName = switch ($errorCode) {
                    1 { 'INVALID_STATE' }
                    2 { 'NOT_PAIRED' }
                    3 { 'PAIRING_TIMEOUT' }
                    4 { 'ESPNOW_ERROR' }
                    5 { 'TIMEOUT' }
                    6 { 'INVALID_COMMAND' }
                    default { 'UNKNOWN' }
                }
                return "success=false`nerror_code=$errorCode`nerror_name=$errorName"
            }
        }
    }

    return $null
}

function Open-NodeBPort {
    $portObj = New-Object System.IO.Ports.SerialPort $Port, $Baud, ([System.IO.Ports.Parity]::None), 8, ([System.IO.Ports.StopBits]::One)
    $portObj.ReadTimeout = $NodeBReadTimeoutMs
    $portObj.WriteTimeout = 12000
    $portObj.DtrEnable = $false
    $portObj.RtsEnable = $false
    $portObj.Open()
    Start-Sleep -Milliseconds 1200
    $portObj.DiscardInBuffer()
    $portObj.DiscardOutBuffer()
    Start-Sleep -Milliseconds 250
    $portObj.DiscardInBuffer()
    $portObj.DiscardOutBuffer()
    $portObj
}

function Invoke-SerialRoundTrip {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Ports.SerialPort]$PortObj,
        [Parameter(Mandatory = $true)]
        [byte[]]$RequestBytes
    )

    $PortObj.Write($RequestBytes, 0, $RequestBytes.Length)
    Read-SerialFrame $PortObj
}

function Read-SerialFrame {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Ports.SerialPort]$PortObj
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($PortObj.ReadTimeout)
    $lenBuf = New-Object byte[] 2
    [void]$PortObj.Read($lenBuf, 0, 2)
    $respLen = [BitConverter]::ToUInt16($lenBuf, 0)

    while ($respLen -lt $NodeBResponseMinLength -or $respLen -gt $NodeBResponseMaxLength) {
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "Invalid response length: $respLen"
        }

        $lenBuf[0] = $lenBuf[1]
        $nextByte = New-Object byte[] 1
        [void]$PortObj.Read($nextByte, 0, 1)
        $lenBuf[1] = $nextByte[0]
        $respLen = [BitConverter]::ToUInt16($lenBuf, 0)
    }

    $respBuf = New-Object byte[] $respLen
    $offset = 0
    while ($offset -lt $respLen) {
        $read = $PortObj.Read($respBuf, $offset, $respLen - $offset)
        if ($read -le 0) {
            throw "Serial read returned 0 before full response"
        }
        $offset += $read
    }

    $all = New-Object byte[] ($respLen + 2)
    [Array]::Copy($lenBuf, 0, $all, 0, 2)
    [Array]::Copy($respBuf, 0, $all, 2, $respLen)
    return $all
}

function Invoke-HardwareCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CodecArgs,
        [Parameter(Mandatory = $true)]
        [System.IO.Ports.SerialPort]$PortObj,
        [string]$DecodeWallet
    )

    $frameHex = Invoke-Codec $CodecArgs
    $requestBytes = Convert-HexToBytes $frameHex
    $responseBytes = Invoke-SerialRoundTrip -PortObj $PortObj -RequestBytes $requestBytes
    $responseHex = Convert-BytesToHex $responseBytes

    Write-Host "raw_response_hex=$responseHex"

    $decoded = Try-DecodeResponse -ResponseBytes $responseBytes -DecodeWallet $DecodeWallet
    if (-not $decoded) {
        throw "Unable to decode Node B response: $responseHex"
    }

    $decoded
}

function Invoke-CodecEncode {
    param([string]$CodecArgs)
    Convert-HexToBytes (Invoke-Codec $CodecArgs)
}

function Convert-DecodedTextToMap {
    param([string]$DecodedText)

    $map = @{}
    foreach ($line in ($DecodedText -split "`r?`n")) {
        if ($line -match '^([^=]+)=(.*)$') {
            $map[$matches[1].Trim()] = $matches[2].Trim()
        }
    }
    $map
}

function Get-NodeBStatus {
    param([System.IO.Ports.SerialPort]$PortObj)
    $decoded = Invoke-HardwareCommand "encode status" $PortObj
    Convert-DecodedTextToMap $decoded
}

function Get-NodeBPeer {
    param([System.IO.Ports.SerialPort]$PortObj)
    $decoded = Invoke-HardwareCommand "encode peer" $PortObj
    Convert-DecodedTextToMap $decoded
}

function Ensure-NodeBPaired {
    param([System.IO.Ports.SerialPort]$PortObj)

    $status = Get-NodeBStatus $PortObj
    if ($status['success'] -ne 'true') {
        throw "Failed to get Node B status"
    }

    if ($status['status_name'] -eq 'Ready') {
        Write-Host "Node B is already in Ready state."
        return
    }

    Invoke-HardwareCommand "encode enter-pairing" $PortObj | Out-Null
    Start-Sleep -Milliseconds 200
    Invoke-HardwareCommand "encode pair --node-a-mac $NodeAMac" $PortObj | Out-Null
    Start-Sleep -Milliseconds 200

    $finalStatus = Get-NodeBStatus $PortObj
    if ($finalStatus['success'] -ne 'true' -or $finalStatus['status_name'] -ne 'Ready') {
        throw "Node B pairing did not reach Ready state"
    }
}

function Prompt-NodeAPairing {
    param([System.IO.Ports.SerialPort]$PortObj)

    $status = Get-NodeBStatus $PortObj
    if ($status['success'] -ne 'true') {
        throw "Failed to get Node B status"
    }

    if ($status['status_name'] -eq 'Ready') {
        $pairDecoded = Invoke-HardwareCommand "encode pair --node-a-mac $NodeAMac" $PortObj
        $pairMap = Convert-DecodedTextToMap $pairDecoded
        if ($pairMap['success'] -ne 'true') {
            throw "Node B failed to prompt pairing: $($pairMap['error_name'])"
        }

        if ($pairMap['payload_text'] -and $pairMap['payload_text'] -ne 'PAIRING_PROMPTED') {
            Write-Host "pair_result=$($pairMap['payload_text'])"
        }

        Write-Host "Node A should now show the pairing screen. Short press approves, long press rejects."
        return
    }

    Ensure-NodeBPaired $PortObj
    Write-Host "Node A should now show the pairing screen. Short press approves, long press rejects."
}

function Invoke-SignDemoFlow {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Ports.SerialPort]$PortObj,
        [Parameter(Mandatory = $true)]
        [string]$ResolvedWallet
    )

    $seq = [UInt32]([UInt64][DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() % 4294967296)
    $requestBytes = Invoke-CodecEncode "encode sign-demo --wallet $ResolvedWallet --to $To --chain-id $ChainId --value-wei $ValueWei --risk $Risk --summary '$Summary' --seq $seq"

    $ackBytes = Invoke-SerialRoundTrip -PortObj $PortObj -RequestBytes $requestBytes
    $ackHex = Convert-BytesToHex $ackBytes
    Write-Host "forward_ack_hex=$ackHex"
    $ackDecoded = Try-DecodeResponse -ResponseBytes $ackBytes -DecodeWallet $ResolvedWallet
    if (-not $ackDecoded) {
        throw "Unable to decode Node B sign forward ack: $ackHex"
    }
    $ackDecoded

    $ackMap = Convert-DecodedTextToMap $ackDecoded
    if ($ackMap['success'] -ne 'true') {
        if ($ackMap['error_name'] -eq 'ESPNOW_ERROR') {
            throw "Node A has not accepted pairing yet, or the radio link is not ready. Run 'nodeb_test.ps1 pair -Port $Port', then short-press the button on Node A, and retry sign-demo."
        }
        throw "Node B rejected sign request before forwarding"
    }

    Write-Host "Node A should now show the signing screen. Short press approves, long press rejects."

    $resultBytes = Read-SerialFrame -PortObj $PortObj
    $resultHex = Convert-BytesToHex $resultBytes
    Write-Host "final_response_hex=$resultHex"
    $resultDecoded = Try-DecodeResponse -ResponseBytes $resultBytes -DecodeWallet $ResolvedWallet
    if (-not $resultDecoded) {
        throw "Unable to decode final Node B response: $resultHex"
    }
    $resultDecoded
}

function Resolve-NodeAWallet {
    if ($Wallet) {
        return $Wallet
    }

    if (Test-Path $walletCachePath) {
        $cached = (Get-Content $walletCachePath -ErrorAction Stop | Select-Object -First 1).Trim()
        if ($cached) {
            Write-Host "Using cached Node A wallet: $cached"
            return $cached
        }
    }

    Write-Host "Detecting Node A wallet from flash on $NodeAPort..."
    if (Test-Path $walletDumpPath) {
        Remove-Item $walletDumpPath -Force
    }

    & C:\Tools\espflash\espflash.exe read-flash -p $NodeAPort -c esp32s3 --before usb-reset --non-interactive 0x9000 0x6000 $walletDumpPath | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $walletDumpPath)) {
        throw "Failed to read mesh_key partition from Node A on $NodeAPort"
    }

    $walletAddress = Invoke-Codec "wallet-from-mesh-key-file --file /mnt/c$($walletDumpPath.Substring(2) -replace '\\','/')"
    if (-not $walletAddress) {
        throw "Failed to derive wallet address from Node A flash"
    }

    Set-Content -Path $walletCachePath -Value $walletAddress -NoNewline
    Write-Host "Detected Node A wallet: $walletAddress"
    return $walletAddress
}

switch ($Command) {
    'wallet' {
        $resolvedWallet = Resolve-NodeAWallet
        Write-Host "node_a_wallet=$resolvedWallet"
        return
    }
    'status' {
        $portObj = Open-NodeBPort
        try {
            Invoke-HardwareCommand "encode status" $portObj
        }
        finally {
            if ($portObj.IsOpen) { $portObj.Close() }
            $portObj.Dispose()
        }
        return
    }
    'enter-pairing' {
        $portObj = Open-NodeBPort
        try {
            Invoke-HardwareCommand "encode enter-pairing" $portObj
        }
        finally {
            if ($portObj.IsOpen) { $portObj.Close() }
            $portObj.Dispose()
        }
        return
    }
    'peer' {
        $portObj = Open-NodeBPort
        try {
            Invoke-HardwareCommand "encode peer" $portObj
        }
        finally {
            if ($portObj.IsOpen) { $portObj.Close() }
            $portObj.Dispose()
        }
        return
    }
    'pair' {
        $portObj = Open-NodeBPort
        try {
            Prompt-NodeAPairing $portObj
        }
        finally {
            if ($portObj.IsOpen) { $portObj.Close() }
            $portObj.Dispose()
        }
        return
    }
    'sign-demo' {
        $resolvedWallet = Resolve-NodeAWallet
        $portObj = Open-NodeBPort
        try {
            Ensure-NodeBPaired $portObj
            Invoke-SignDemoFlow -PortObj $portObj -ResolvedWallet $resolvedWallet
        }
        finally {
            if ($portObj.IsOpen) { $portObj.Close() }
            $portObj.Dispose()
        }
        return
    }
}
