import "pe"

rule Hunting_resources_noimps {
    meta:
        author = "@captainGeech42"
        description = "Look for PE files that have a resource but don't import the resource access APIs"
        date = "2024-01-21"
        version = "1"
        DaysofYARA = "20/100"
    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3c)) == 0x00004550 and
        not (
            pe.imports("kernel32.dll", "FindResourceA") or
            pe.imports("kernel32.dll", "FindResourceEx") or
            pe.imports("kernel32.dll", "LoadResource") or
            pe.imports("kernel32.dll", "LockResource")
        ) and
        for any section in pe.sections : (
            section.name == ".rsrc"
        )
}