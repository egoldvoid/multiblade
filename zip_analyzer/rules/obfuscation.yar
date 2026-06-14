rule Obfuscation_PowerShell_EncodedCommand {
    meta:
        description = "PowerShell encoded command with anti-analysis flags — LOLBAS obfuscation"
        severity = "high"
        mitre = "T1027.010"
        family = "Obfuscation"
    strings:
        $ps = "powershell" nocase
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $nop = "-nop" nocase
        $hide = "-w hidden" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
    condition:
        $ps and any of ($enc1, $enc2) and any of ($nop, $hide, $bypass)
}

// NOTE: LargeBase64Payload (pure character-class regex over large data) was
// removed — YARA's NFA engine is O(n²) on all-alphanumeric files for this
// pattern. The equivalent detection runs in checks.py:check_suspicious_strings
// via Python's re module, which is safe for the 65 KB read cap.
//
// NOTE: HexEncodedShellcode (/\\x[0-9a-fA-F]{2}.../) was benchmarked at <1ms
// on 64 KB inputs and is safe to keep, but is omitted here because the literal
// \x prefix is almost never present in real binaries (they use raw bytes).
// Keeping it would cause false negatives without adding true positives.
