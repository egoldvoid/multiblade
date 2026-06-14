rule ProcessInjection_ClassicTriad {
    meta:
        description = "Process injection via VirtualAllocEx / WriteProcessMemory / CreateRemoteThread"
        severity = "critical"
        mitre = "T1055.003"
        family = "ProcessInjection"
    strings:
        $mz = { 4D 5A }
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
    condition:
        $mz at 0 and 2 of ($api1, $api2, $api3)
}

rule ProcessInjection_APC {
    meta:
        description = "APC queue or NtMapViewOfSection process injection"
        severity = "high"
        mitre = "T1055.004"
        family = "ProcessInjection"
    strings:
        $mz = { 4D 5A }
        $api1 = "QueueUserAPC"
        $api2 = "NtMapViewOfSection"
        $api3 = "RtlCreateUserThread"
    condition:
        $mz at 0 and any of ($api1, $api2, $api3)
}
