rule SUSP_PE_DRIVER_KM_UM_COMM_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule looking for suspicious drivers using socket-um from km-um-communication."
        reference   = "https://github.com/adspro15/km-um-communication/blob/046c1108552f9138bb3420bf1716da6ca20ff71a/socket-um/server_shared.h#L4"
        reference   = "https://twitter.com/7odaZohdy/status/1747607830033539262"
        vtsearch    = "content:{817c2420685534127518}"

        DaysofYARA  = "10/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-27"
        version     = "1.0"

        hash        = "821e9fe79677dfd89ae5b54e4a14444bbad6c4977d945da68cabf9b421524972"
        hash        = "801916b99439e20b1fa9813735e3d8b41d815057a6b4b1bc67ed5b3a3e9bd02c"

    strings:
        // cmp dword [rsp+0x20], 0x12345568
        // jne 0x140002087
        $ = {817c2420685534127518}

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x18) == 0x20b
        and uint16(uint32(0x3C)+0x5C) == 0x0001
        and all of them
}
