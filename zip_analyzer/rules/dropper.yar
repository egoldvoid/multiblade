rule Dropper_PowerShell_IEX {
    meta:
        description = "PowerShell Invoke-Expression downloading and executing remote content"
        severity = "high"
        mitre = "T1059.001"
        family = "Dropper"
    strings:
        $iex1 = "iex(" nocase
        $iex2 = "Invoke-Expression" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "WebClient" nocase
        $dl4 = "Webclient" nocase
    condition:
        any of ($iex1, $iex2) and any of ($dl1, $dl2, $dl3, $dl4)
}

rule Dropper_PowerShell_Download {
    meta:
        description = "PowerShell download-and-execute to temp or system path"
        severity = "high"
        mitre = "T1105"
        family = "Dropper"
    strings:
        $dl1 = "DownloadFile" nocase
        $dl2 = "DownloadString" nocase
        $path1 = "$env:TEMP" nocase
        $path2 = "System32" nocase
        $path3 = "AppData" nocase
    condition:
        any of ($dl1, $dl2) and any of ($path1, $path2, $path3)
}

rule Dropper_Python_ExecDecode {
    meta:
        description = "Python base64 decode followed by exec — in-memory dropper"
        severity = "high"
        mitre = "T1059.006"
        family = "Dropper"
    strings:
        $b64 = "base64" nocase
        $decode = "b64decode" nocase
        $exec = "exec("
    condition:
        $b64 and $decode and $exec
}

rule Dropper_WgetCurl_Exec {
    meta:
        description = "Shell script downloading executable then running it"
        severity = "high"
        mitre = "T1105"
        family = "Dropper"
    strings:
        $dl1 = "wget " nocase
        $dl2 = "curl " nocase
        $exec1 = "chmod +x" nocase
        $exec2 = "bash " nocase
        $exec3 = "/bin/sh" nocase
    condition:
        any of ($dl1, $dl2) and any of ($exec1, $exec2, $exec3)
}
