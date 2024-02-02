rule SUSP_PE_MICROOLAP_PACKET_SNIFFER_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "In non-DLL PE files this string has a surprisingly low presence."
        vt          = "tag:peexe content:pssdk41.vxd"

        DaysofYARA  = "28/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-31"
        version     = "1.0"

        hash        = "4a864dd61ee125e06f3639b25d0f4021a357212ddb5bb4b0c3fdd58fe80fc983"
        hash        = "da971fc4631cda4fece986616fb17f25154fd3dc51123d6867cc0aeafbc5a7c6"
        hash        = "bc0cd56f28ebf60301c369092173e6f8c9255bf8b1413ccd1b07b41a9a0a5194"
        hash        = "61f5f3de658f9e226a622cac1513d15de2e75ca09988dfd84d0ce1d4a57da809"
        hash        = "ace81e9862d5312bd06a1139e592dac5bbecb812b502894af2af3211a411a6bd"
        hash        = "eaca771c7085ca931ecfe1c4271fde87266f9d28bf5b254f380ae268704be8b9"
        hash        = "dcbf039720d45d385de73034165ad059936ee3472cbf21c6a5b0aa3b0245c43c"
        hash        = "c1a021240cfdf2d76d69f0d5254bc0c5b07998be30ced655a80290bf840fb4ef"

    strings:
        $   = "pssdk41.vxd"

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x18) == 0x10b
        and (uint16(uint32(0x3C)+0x16) & 0x2000) != 0x2000
        and all of them
}
