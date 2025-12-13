# MCP Remote Agent - Windows PowerShell
# Usage: irm https://${DOMAIN}/agent/windows -Body @{server="ws://your-domain:3103"} | iex
# Or: .\windows.ps1 -Server "ws://your-server:3103" -Secret "your-secret" -Id "MYPC"

param(
    [string]$Server = "ws://${DOMAIN}:3103",
    [string]$Secret = "AGENT_SECRET_PLACEHOLDER",
    [string]$Id = $env:COMPUTERNAME
)

$script:cmdCount = 0

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  MCP REMOTE AGENT - Windows" -F Cyan
    Write-Host "  ==========================" -F DarkGray
    Write-Host ""
}

function Log([string]$M, [string]$T = "INFO") {
    $time = Get-Date -Format "HH:mm:ss"
    $col = @{INFO="Cyan";OK="Green";WARN="Yellow";ERR="Red";CMD="Magenta"}
    Write-Host "  [$time] " -F DarkGray -NoNewline
    Write-Host "[$T] " -F $col[$T] -NoNewline
    Write-Host $M -F White
}

function Take-Screenshot {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
        $stream = New-Object System.IO.MemoryStream
        $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
        $base64 = [Convert]::ToBase64String($stream.ToArray())
        $stream.Dispose()
        $bitmap.Dispose()
        $graphics.Dispose()
        return @{success=$true; base64=$base64}
    } catch {
        return @{success=$false; error="$_"}
    }
}

function Run($c, $a) {
    switch($c) {
        "shell" {
            try {
                $output = Invoke-Expression $a.cmd 2>&1 | Out-String
                @{success=$true; stdout=$output; stderr=""; exitCode=0}
            } catch {
                @{success=$false; stdout=""; stderr="$_"; exitCode=1}
            }
        }
        "powershell" {
            try {
                $output = Invoke-Expression $a.cmd 2>&1 | Out-String
                @{success=$true; output=$output}
            } catch {
                @{success=$false; error="$_"}
            }
        }
        "file_read" {
            try {
                @{success=$true; content=[IO.File]::ReadAllText($a.path)}
            } catch {
                @{success=$false; error="$_"}
            }
        }
        "file_write" {
            try {
                [IO.File]::WriteAllText($a.path, $a.content)
                @{success=$true}
            } catch {
                @{success=$false; error="$_"}
            }
        }
        "file_list" {
            try {
                $p = if($a.path){$a.path}else{"."}
                @{success=$true; files=@(Get-ChildItem $p | ForEach-Object {
                    @{name=$_.Name; type=$(if($_.PSIsContainer){"dir"}else{"file"}); size=$_.Length}
                })}
            } catch {
                @{success=$false; error="$_"}
            }
        }
        "system_info" {
            $os = Get-CimInstance Win32_OperatingSystem
            @{
                success=$true
                hostname=$env:COMPUTERNAME
                platform="Windows"
                arch=$env:PROCESSOR_ARCHITECTURE
                version=$os.Version
                user=$env:USERNAME
                domain=$env:USERDOMAIN
            }
        }
        "process_list" {
            @{success=$true; processes=@(Get-Process | Select-Object -First 50 | ForEach-Object {
                @{name=$_.Name; pid=$_.Id; mem=$_.WorkingSet64}
            })}
        }
        "screenshot" {
            Take-Screenshot
        }
        "download" {
            try {
                Invoke-WebRequest -Uri $a.url -OutFile $a.path
                @{success=$true; path=$a.path}
            } catch {
                @{success=$false; error="$_"}
            }
        }
        "status" {
            @{success=$true; id=$Id; host=$env:COMPUTERNAME; time="$(Get-Date -Format o)"}
        }
        default {
            @{success=$false; error="Unknown command: $c"}
        }
    }
}

Show-Banner
Log "Agent ID: $Id" "INFO"
Log "Server: $Server" "INFO"
Write-Host ""

while($true) {
    $ws = $null
    try {
        Log "Connecting to server..." "INFO"
        $ws = New-Object Net.WebSockets.ClientWebSocket
        $null = $ws.ConnectAsync($Server, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
        Log "Connected!" "OK"

        # Register
        $regMsg = @{
            type = "register"
            clientId = $Id
            authSecret = $Secret
            hostname = $env:COMPUTERNAME
            platform = "Windows"
            arch = $env:PROCESSOR_ARCHITECTURE
            username = $env:USERNAME
        } | ConvertTo-Json -Compress

        $bytes = [Text.Encoding]::UTF8.GetBytes($regMsg)
        $null = $ws.SendAsync([ArraySegment[byte]]::new($bytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()

        $buf = [byte[]]::new(1048576)  # 1MB buffer for screenshots

        while($ws.State -eq 'Open') {
            try {
                $seg = [ArraySegment[byte]]::new($buf)
                $res = $ws.ReceiveAsync($seg, [Threading.CancellationToken]::None).GetAwaiter().GetResult()

                if($res.MessageType -eq 'Close') {
                    Log "Server closed connection" "WARN"
                    break
                }

                $json = [Text.Encoding]::UTF8.GetString($buf, 0, $res.Count)
                $msg = $json | ConvertFrom-Json

                switch($msg.type) {
                    "registered" {
                        Log "Registered as: $($msg.clientId)" "OK"
                    }
                    "ping" {
                        $pong = '{"type":"pong"}'
                        $pbytes = [Text.Encoding]::UTF8.GetBytes($pong)
                        $null = $ws.SendAsync([ArraySegment[byte]]::new($pbytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
                    }
                    "command" {
                        $script:cmdCount++
                        Log "Command: $($msg.command)" "CMD"

                        $result = Run $msg.command $msg.args

                        $resp = @{
                            type = "command_response"
                            commandId = $msg.commandId
                            result = $result
                        } | ConvertTo-Json -Compress -Depth 10

                        $rbytes = [Text.Encoding]::UTF8.GetBytes($resp)
                        $null = $ws.SendAsync([ArraySegment[byte]]::new($rbytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()

                        if($result.success) {
                            Log "Command completed successfully" "OK"
                        } else {
                            Log "Command failed: $($result.error)" "ERR"
                        }
                    }
                }
            } catch {
                Log "Error: $_" "ERR"
                break
            }
        }
    } catch {
        Log "Connection error: $_" "ERR"
    } finally {
        if($ws) {
            try { $ws.Dispose() } catch {}
        }
    }

    Log "Reconnecting in 5 seconds..." "WARN"
    Start-Sleep 5
}
