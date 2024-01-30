rule SUSP_ELF_SEA_TURTLE_SOCAT_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find suspected SOCAT variant used by Sea Turtle."
        reference   = "https://www.huntandhackett.com/blog/turkish-espionage-campaigns"

        DaysofYARA  = "16/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-29"
        version     = "1.0"

        hash        = "71c81cb46dd1903f12f3aef844b0fc559f31e2f613a8ae91ffb5630bc7011ef5"

    strings:
        $ = {458a1141??????74??4d8d61014c39e674??450fb6610141??????41c1e2084509e285c079??498d410229d04d63ca4939e97d??4901f9eb??4584d274??4939cb4989cc74??4d8d630141??????450fb6194d8d69014989f24d29ea4d39d37d??4d89c24d29e24d39d37d??4531d24d39da74??478a7411014788341449ffc2eb??85c041c603??79??498d410129d0eb??4f8d1c144f8d4c15??4883c302e9????????5b5d}

    condition:
        uint32(0) == 0x464c457f
        and all of them
}
