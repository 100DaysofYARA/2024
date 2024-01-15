rule Dockerfile_classifier_weak {
    meta:
        author = "@captainGeech42"
        description = "[WEAK SIGNAL] Look for possible Dockerfiles."
        date = "2024-01-09"
        version = "1"
        DaysofYARA = "9/100"
        reference = "https://docs.docker.com/engine/reference/builder/#overview"
    strings:
        $cmd1 = "add" nocase fullword
        $cmd2 = "arg" nocase fullword
        $cmd3 = "cmd" nocase fullword
        $cmd4 = "copy" nocase fullword
        $cmd5 = "entrypoint" nocase fullword
        $cmd6 = "env" nocase fullword
        $cmd7 = "expose" nocase fullword
        $cmd8 = "from" nocase fullword
        $cmd9 = "healthcheck" nocase fullword
        $cmd10 = "label" nocase fullword
        $cmd11 = "maintainer" nocase fullword
        $cmd12 = "onbuild" nocase fullword
        $cmd13 = "run" nocase fullword
        $cmd14 = "shell" nocase fullword
        $cmd15 = "stopsignal" nocase fullword
        $cmd16 = "user" nocase fullword
        $cmd17 = "volume" nocase fullword
        $cmd18 = "workdir" nocase fullword

        $fp1 = "@echo off"
        $fp2 = "[Desktop Entry]"
        $fp3 = "<html"
        $fp4 = "import "
    condition:
        // filter out json files
        uint8(0) != 0x5b and // '['
        uint8(0) != 0x7b and // '{'

        filesize < 2KB and
        4 of ($cmd*) and
        none of ($fp*)
}

rule Dockerfile_classifier_strong {
    meta:
        author = "@captainGeech42"
        description = "[STRONG SIGNAL] Look for possible Dockerfiles."
        date = "2024-01-09"
        version = "1"
        DaysofYARA = "9/100"
        reference = "https://docs.docker.com/engine/reference/builder/#overview"
    strings:
        $cmd1 = "add" nocase fullword
        $cmd2 = "arg" nocase fullword
        $cmd3 = "cmd" nocase fullword
        $cmd4 = "copy" nocase fullword
        $cmd5 = "entrypoint" nocase fullword
        $cmd6 = "env" nocase fullword
        $cmd7 = "expose" nocase fullword
        $cmd8 = "from" nocase fullword
        $cmd9 = "healthcheck" nocase fullword
        $cmd10 = "label" nocase fullword
        $cmd11 = "maintainer" nocase fullword
        $cmd12 = "onbuild" nocase fullword
        $cmd13 = "run" nocase fullword
        $cmd14 = "shell" nocase fullword
        $cmd15 = "stopsignal" nocase fullword
        $cmd16 = "user" nocase fullword
        $cmd17 = "volume" nocase fullword
        $cmd18 = "workdir" nocase fullword
    condition:
        // filter out json files
        uint8(0) != 0x5b and // '['
        uint8(0) != 0x7b and // '{'

        filesize < 5KB and
        8 of ($cmd*) and

        // certain dockerfile commands are far more likely
        $cmd8 and
        $cmd13 and
        $cmd1 and
        ($cmd5 or $cmd3)
}
