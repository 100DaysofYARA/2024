import "pe"
import "hash"
rule RichHash_Hunting
{
    meta:
        author = "Thomas Roccia | @fr0gger_"
        description = "100DaysOfYara RichHash hunting for mimikatz dll"
        sample = "aef6ce3014add838cf676b57957d630cd2bb15b0c9193cf349bcffecddbc3623"
    condition:
        hash.md5(pe.rich_signature.clear_data) == "8a0f7bc19a66091ff7eea991e1903d09"
}
