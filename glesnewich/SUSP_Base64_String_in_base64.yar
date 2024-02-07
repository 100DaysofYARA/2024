rule SUSP_Base64_String_in_base64
{
    meta:
        author = "Greg Lesnewich"
        description = "look for the string base64, encoded in base64, which just seems odd"
        date = "2024-02-06"
        version = "1.0"
        DaysOfYara = "37/100"

    strings:
        $ = "base64" base64 base64wide
    condition:
        all of them
}
