import "pe"
import "console"

// this will write out a new yara rule for the rich_signature key for every sample scanned
// if you run it over a large corpus, it will generate thousands, some of them might be the same
private rule rulewriter_rich_signature_key {
    meta:
        author = "stvemillertime"
    condition:
        uint16be(0) == 0x4d5a 
        and pe.number_of_signatures == 0
        and (console.hex("rule pe_rich_header_",pe.rich_signature.key)
        and console.log("{")
        and console.log("   meta:")
        and console.log("       author = \"stvemillertime\"")
        and console.log("       desc = \"rules for rich sig keys\"")
        and console.log("   condition:")
        and console.log("       uint16be(0) == 0x4d5a")
        and console.log("       and pe.number_of_signatures == 0")
        and console.hex("       and pe.rich_signature.key == ",pe.rich_signature.key)
        and console.log("}"))
}
