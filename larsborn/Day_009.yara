rule Algorithm_DESBuffers
{
    meta:
        description = "Constants from DES implementation"
        author = "@larsborn"
        date = "2020-08-22"
        reference = "https://github.com/tarequeh/DES/blob/master/des.c"
        example_hash_01 = "0b38ca277bbb042d43bd1f17c4e424e167020883526eb2527ba929b2f0990a8f"

        DaysofYARA = "9/100"
    strings:
        $initial_key_permutaion = {
            39 31 29 21 19 11 09 01 3a 32 2a 22 1a 12 0a 02
            3b 33 2b 23 1b 13 0b 03 3c 34 2c 24 3f 37 2f 27
            1f 17 0f 07 3e 36 2e 26 1e 16 0e 06 3d 35 2d 25
            1d 15 0d 05 1c 14 0c 04
        }
        $initial_message_permutation = {
            3a 32 2a 22 1a 12 0a 02 3c 34 2c 24 1c 14 0c 04
            3e 36 2e 26 1e 16 0e 06 40 38 30 28 20 18 10 08
            39 31 29 21 19 11 09 01 3b 33 2b 23 1b 13 0b 03
            3d 35 2d 25 1d 15 0d 05 3f 37 2f 27 1f 17 0f 07
        }
        $sub_key_permutation = {
            0e 11 0b 18 01 05 03 1c 0f 06 15 0a 17 13 0c 04
            1a 08 10 07 1b 14 0d 02 29 34 1f 25 2f 37 1e 28
            33 2d 21 30 2c 31 27 38 22 35 2e 2a 32 24 1d 20
        }
        $S1 = {
            0e 04 0d 01 02 0f 0b 08 03 0a 06 0c 05 09 00 07
            00 0f 07 04 0e 02 0d 01 0a 06 0c 0b 09 05 03 08
            04 01 0e 08 0d 06 02 0b 0f 0c 09 07 03 0a 05 00
            0f 0c 08 02 04 09 01 07 05 0b 03 0e 0a 00 06 0d
        }
        $S2 = {
            0f 01 08 0e 06 0b 03 04 09 07 02 0d 0c 00 05 0a
            03 0d 04 07 0f 02 08 0e 0c 00 01 0a 06 09 0b 05
            00 0e 07 0b 0a 04 0d 01 05 08 0c 06 09 03 02 0f
            0d 08 0a 01 03 0f 04 02 0b 06 07 0c 00 05 0e 09
        }
        $S3 = {
            0a 00 09 0e 06 03 0f 05 01 0d 0c 07 0b 04 02 08
            0d 07 00 09 03 04 06 0a 02 08 05 0e 0c 0b 0f 01
            0d 06 04 09 08 0f 03 00 0b 01 02 0c 05 0a 0e 07
            01 0a 0d 00 06 09 08 07 04 0f 0e 03 0b 05 02 0c
        }
        $S4 = {
            07 0d 0e 03 00 06 09 0a 01 02 08 05 0b 0c 04 0f
            0d 08 0b 05 06 0f 00 03 04 07 02 0c 01 0a 0e 09
            0a 06 09 00 0c 0b 07 0d 0f 01 03 0e 05 02 08 04
            03 0f 00 06 0a 01 0d 08 09 04 05 0b 0c 07 02 0e
        }
        $S5 = {
            02 0c 04 01 07 0a 0b 06 08 05 03 0f 0d 00 0e 09
            0e 0b 02 0c 04 07 0d 01 05 00 0f 0a 03 09 08 06
            04 02 01 0b 0a 0d 07 08 0f 09 0c 05 06 03 00 0e
            0b 08 0c 07 01 0e 02 0d 06 0f 00 09 0a 04 05 03
        }
        $S6 = {
            0c 01 0a 0f 09 02 06 08 00 0d 03 04 0e 07 05 0b
            0a 0f 04 02 07 0c 09 05 06 01 0d 0e 00 0b 03 08
            09 0e 0f 05 02 08 0c 03 07 00 04 0a 01 0d 0b 06
            04 03 02 0c 09 05 0f 0a 0b 0e 01 07 06 00 08 0d
        }
        $S7 = {
            04 0b 02 0e 0f 00 08 0d 03 0c 09 07 05 0a 06 01
            0d 00 0b 07 04 09 01 0a 0e 03 05 0c 02 0f 08 06
            01 04 0b 0d 0c 03 07 0e 0a 0f 06 08 00 05 09 02
            06 0b 0d 08 01 04 0a 07 09 05 00 0f 0e 02 03 0c
        }
        $S8 = {
            0d 02 08 04 06 0f 0b 01 0a 09 03 0e 05 00 0c 07
            01 0f 0d 08 0a 03 07 04 0c 05 06 0b 00 0e 09 02
            07 0b 04 01 09 0c 0e 02 00 06 0a 0d 0f 03 05 08
            02 01 0e 07 04 0a 08 0d 0f 0c 09 00 03 05 06 0b
        }
        $right_sub_message_permutation = {
            10 07 14 15 1d 0c 1c 11 01 0f 17 1a 05 12 1f 0a
            02 08 18 0e 20 1b 03 09 13 0d 1e 06 16 0b 04 19
        }
        $final_message_permutation =  {
            28 08 30 10 38 18 40 20 27 07 2f 0f 37 17 3f 1f
            26 06 2e 0e 36 16 3e 1e 25 05 2d 0d 35 15 3d 1d
            24 04 2c 0c 34 14 3c 1c 23 03 2b 0b 33 13 3b 1b
            22 02 2a 0a 32 12 3a 1a 21 01 29 09 31 11 39 19
        }
    condition:
        any of them
}
