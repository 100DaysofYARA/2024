rule TritonPythonScripts_01
{
    meta:
        description = "Strings and buffers from the Python-based component of the Triton/Trisis/HatMan activity"
        author = "@larsborn"
        date = "2024-01-18"
        reference = "https://github.com/MDudek-ICS/TRISIS-TRITON-HATMAN"
        example_hash_01 = "d0b016b765df33c2d41eeb3ec4e17df9005d81c8ef869db0883b10783a22ad3c"
        example_hash_02 = "c918a6f3fd5b18b0e427ff025d388c76b0916374c88b9fe968534eea94fd6948"
        example_hash_04 = "ea3bf5b11af2a9a712cbb38c936be96e8b15eb9566359a3ff7c5302b0617989d"
        example_hash_05 = "5a22f23736a1489677570ee530696602abf21fa188d0c31f3bd48c0911c69bfc"
        example_hash_06 = "16a7ecc3a79b627aca527a8747ad8e461da1f00d9895947e2fc38d958b4d72a7"
        example_hash_07 = "86455bec309c740eae8fec8b7fa5c4c561ffb57232d97d47b51157364f2fa28a"

        DaysofYARA = "12/100"
    strings:
        $error_msg_01 = "exception FIXED by REMOVING our code"
        $error_msg_02 = "NOT fixed! Total Failure"
        $error_msg_03 = "cannot parse PROG TABLE"
        $error_msg_04 = "main code write FAILED!"
        $error_msg_05 = "force removing the code, no checks"
        $payload_01_raw = "\x80\x00@<\x00\x00b\x80@\x00\x80<@ \x03|"
        $payload_01_txt = "\\x80\\x00@<\\x00\\x00b\\x80@\\x00\\x80<@ \\x03|"
        $payload_02_raw = "\xff\xff`8\x02\x00\x00D \x00\x80N"
        $payload_02_txt = "\\xff\\xff`8\\x02\\x00\\x00D \\x00\\x80N"
    condition:
        any of them
}
