import "elf"

rule SUSP_ELF_HOOKS_1
{
    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find suspicious ELF shared-object files that might be hooking functions."

        DaysofYARA  = "33/100"

        license     = "BSD-2-Clause"
        date        = "2024-02-08"
        version     = "1.0"

        hash        = "f54edb0b09e43f3670870034415a446969f5dfffc49b499795d4cfa3aebd8b3a"

    condition:
        uint32(0) == 0x464c457f
        and elf.type == elf.ET_DYN
        and elf.dynsym_entries > 0

        /*
            Essentially a template that can be tuned to desired hunting
            criteria.
        */
        and for 3 dynsym in elf.dynsym : (
            (
                dynsym.name == "get_source_name"
                or dynsym.name == "getpeername"
                or dynsym.name startswith "accept"
            )
            and dynsym.size >  2
            and dynsym.type  == 2
            and dynsym.bind  == 1
        )
}
