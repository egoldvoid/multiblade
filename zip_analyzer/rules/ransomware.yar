rule Ransomware_FileEncryption {
    meta:
        description = "File encryption using Windows CNG/CAPI — ransomware pattern"
        severity = "critical"
        mitre = "T1486"
        family = "Ransomware"
    strings:
        $mz = { 4D 5A }
        $api1 = "CryptEncrypt"
        $api2 = "BCryptEncrypt"
    condition:
        $mz at 0 and any of ($api1, $api2)
}

rule Ransomware_Note {
    meta:
        description = "File content matches known ransomware ransom note patterns"
        severity = "critical"
        mitre = "T1486"
        family = "Ransomware"
    strings:
        $n1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $n2 = "bitcoin" nocase
        $n3 = "BTC" nocase
        $n4 = "decrypt" nocase
        $n5 = ".onion" nocase
        $n6 = "RSA-" nocase
        $n7 = "AES-" nocase
    condition:
        3 of them
}

rule Ransomware_FileSearch {
    meta:
        description = "Mass file enumeration pattern combined with encryption API — ransomware behavior"
        severity = "critical"
        mitre = "T1486"
        family = "Ransomware"
    strings:
        $mz = { 4D 5A }
        $enum1 = "FindFirstFileW"
        $enum2 = "FindNextFileW"
        $crypt1 = "CryptEncrypt"
        $crypt2 = "BCryptEncrypt"
        $reg = "RegSetValueEx"
    condition:
        $mz at 0 and any of ($enum1, $enum2) and (any of ($crypt1, $crypt2) or $reg)
}
