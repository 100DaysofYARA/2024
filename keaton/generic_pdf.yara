import "console"
rule pdf_comment_values
{
    meta:
        author = "kyle eaton"
        date = "02/12/2024"
        day = "1/100"
        description = "this is not the whole comment, just a quick similarity check."
    strings:
        $pdf = {25 50 44 46 2d}
    condition:
        $pdf at 0 and 
        console.hex(uint32be(9))
}

rule pdf_comment_present
{
    meta:
        author = "kyle eaton"
        date = "02/12/2024"
        day = "2/100"
    strings:
        $pdf = {25 50 44 46 2d}
    condition:
        $pdf at 0 and 
        uint8(9) != 0x31
}

rule pdf_comment_present_stringless
{
    meta:
        author = "kyle eaton"
        date = "02/12/2024"
        day = "3/100"
    condition:
    // this header check isn't really needed like this, just trying to remember this idea from greg.
        uint32be(0) == 0x25504446 and 
        uint32be(1) == 0x5044462d and 
        uint8(8) == 0x0d
}

rule pdf_print_version
{
    meta:
        author = "kyle eaton"
        date = "02/13/2024"
        day = "4/100"
    condition:
        uint32be(0) == 0x25504446 and
        console.hex("PDF VERSION:", uint32be(5))

}

