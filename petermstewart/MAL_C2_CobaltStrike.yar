rule MAL_CobaltStrike_Powershell_loader {
    meta:
        description = "Matches strings found in CobaltStrike PowerShell loader samples."
        last_modified = "2024-02-09"
        author = "@petermstewart"
        DaysofYara = "40/100"
        sha256 = "9c9e8841d706406bc23d05589f77eec6f8df6d5e4076bc6a762fdb423bfe8c24"
        sha256 = "6881531ab756d62bdb0c3279040a5cbe92f9adfeccb201cca85b7d3cff7158d3"
        ref = "https://medium.com/@cybenfolland/deobfuscating-a-powershell-cobalt-strike-beacon-loader-c650df862c34"
        ref = "https://forensicitguy.github.io/inspecting-powershell-cobalt-strike-beacon/"

    strings:
        $a1 = "=New-Object IO.MemoryStream("
        $a2 = "[Convert]::FromBase64String("
        $a3 = "IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
        $b1 = "Set-StrictMode -Version 2"
        $b2 = "$DoIt = @'"
        $b3 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($DoIt))"
        $b4 = "start-job { param($a) IEX $a }"

    condition:
        all of ($a*) or
        all of ($b*)
}

rule MAL_CobaltStrike_Powershell_loader_base64 {
    meta:
        description = "Matches base64-encoded strings found in CobaltStrike PowerShell loader commands."
        last_modified = "2024-02-10"
        author = "@petermstewart"
        DaysofYara = "41/100"

    strings:
        $a1 = "=New-Object IO.MemoryStream(" base64 wide
        $a2 = "[Convert]::FromBase64String(" base64 wide
        $a3 = "IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()" base64 wide

    condition:
        all of them
}
