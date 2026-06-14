rule Webshell_PHP_CommandExec {
    meta:
        description = "PHP code execution webshell via system/exec/passthru with user input"
        severity = "high"
        mitre = "T1505.003"
        family = "Webshell"
    strings:
        $php = "<?php" nocase
        $cmd1 = "system(" nocase
        $cmd2 = "exec(" nocase
        $cmd3 = "passthru(" nocase
        $cmd4 = "shell_exec(" nocase
        $input1 = "$_GET"
        $input2 = "$_POST"
        $input3 = "$_REQUEST"
    condition:
        $php and any of ($cmd1, $cmd2, $cmd3, $cmd4) and any of ($input1, $input2, $input3)
}

rule Webshell_PHP_EvalObfuscated {
    meta:
        description = "PHP eval with base64 decoding — obfuscated dropper or webshell"
        severity = "high"
        mitre = "T1505.003"
        family = "Webshell"
    strings:
        $php = "<?php" nocase
        $eval = "eval(" nocase
        $b64 = "base64_decode" nocase
    condition:
        $php and $eval and $b64
}

rule Webshell_PHP_FileWrite {
    meta:
        description = "PHP writing arbitrary content to a file — backdoor installer"
        severity = "high"
        mitre = "T1505.003"
        family = "Webshell"
    strings:
        $php = "<?php" nocase
        $fw1 = "file_put_contents" nocase
        $fw2 = "fwrite(" nocase
        $input1 = "$_GET"
        $input2 = "$_POST"
        $input3 = "$_REQUEST"
    condition:
        $php and any of ($fw1, $fw2) and any of ($input1, $input2, $input3)
}
