rule HUNT_PYC_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule looking at Python PYC files."
        reference   = "https://github.com/corkami/pics/blob/master/binary/pyc.png"

        DaysofYARA  = "9/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-09"
        version     = "1.0"

        hash        = "3f2e956b28cd3baf75b608074eb3f63ce9dc78eb6302d43c35993c853961a57d"

    condition:
        uint32be(0) == 0x330d0d0a           // python version
        and uint32be(0x4) == 0x00000000     // flags
        and uint32be(0x8) == 0x00000000     // timestamps
        and uint32be(0xc) == 0xe3000000     // original source size
}
