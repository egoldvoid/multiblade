rule CredentialDumping_LSASS {
    meta:
        description = "LSASS memory dump via MiniDumpWriteDump — credential harvesting"
        severity = "critical"
        mitre = "T1003.001"
        family = "CredentialTheft"
    strings:
        $mz = { 4D 5A }
        $api = "MiniDumpWriteDump"
    condition:
        $mz at 0 and $api
}

rule CredentialDumping_SAM {
    meta:
        description = "Direct SAM or LSA secrets access — credential theft"
        severity = "critical"
        mitre = "T1003.002"
        family = "CredentialTheft"
    strings:
        $mz = { 4D 5A }
        $api1 = "SamIConnect"
        $api2 = "LsaRetrievePrivateData"
    condition:
        $mz at 0 and any of ($api1, $api2)
}

rule CredentialDumping_DPAPI {
    meta:
        description = "DPAPI credential decryption via CryptUnprotectData"
        severity = "high"
        mitre = "T1555"
        family = "CredentialTheft"
    strings:
        $mz = { 4D 5A }
        $api = "CryptUnprotectData"
    condition:
        $mz at 0 and $api
}
