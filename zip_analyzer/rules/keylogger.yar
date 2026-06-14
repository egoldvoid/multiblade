rule Keylogger_WindowsHook {
    meta:
        description = "Windows keyboard/mouse hook installation — keylogger"
        severity = "high"
        mitre = "T1056.001"
        family = "Keylogger"
    strings:
        $mz = { 4D 5A }
        $api1 = "SetWindowsHookEx"
        $api2 = "GetAsyncKeyState"
        $api3 = "GetRawInputData"
    condition:
        $mz at 0 and any of ($api1, $api2, $api3)
}
