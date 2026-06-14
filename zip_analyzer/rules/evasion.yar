rule Evasion_VMEnvironmentDetection {
    meta:
        description = "Multiple VM and sandbox environment detection strings — will refuse to run in analysis"
        severity = "high"
        mitre = "T1497"
        family = "SandboxEvasion"
    strings:
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "VBOX" nocase
        $vm4 = "QEMU" nocase
        $vm5 = "SbieDll" nocase
        $vm6 = "vmtoolsd" nocase
        $vm7 = "vboxguest" nocase
        $vm8 = "wireshark" nocase
        $vm9 = "ollydbg" nocase
        $vm10 = "procmon" nocase
    condition:
        3 of them
}

rule Evasion_AntiDebugMulti {
    meta:
        description = "Multiple anti-debugging techniques in a single PE binary"
        severity = "high"
        mitre = "T1622"
        family = "AntiDebug"
    strings:
        $mz = { 4D 5A }
        $api1 = "IsDebuggerPresent"
        $api2 = "CheckRemoteDebuggerPresent"
        $api3 = "NtQueryInformationProcess"
        $api4 = "OutputDebugString"
    condition:
        $mz at 0 and 2 of ($api1, $api2, $api3, $api4)
}

rule Evasion_WMIPersistence {
    meta:
        description = "WMI event subscription for persistent script execution"
        severity = "high"
        mitre = "T1546.003"
        family = "WMIPersistence"
    strings:
        $wmi1 = "__EventFilter" nocase
        $wmi2 = "ActiveScriptEventConsumer" nocase
        $wmi3 = "CommandLineEventConsumer" nocase
        $wmi4 = "SELECT * FROM __InstanceModificationEvent" nocase
        $wmi5 = "__FilterToConsumerBinding" nocase
    condition:
        2 of them
}
