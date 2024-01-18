rule Algorithm_AESSBoxes
{
    meta:
        description = "AES Forward S-box and Reverse S-box"
        author = "@larsborn"
        date = "2020-08-23"
        reference = "https://en.wikipedia.org/wiki/Rijndael_S-box"
        example_hash_01_PyXie = "ed675db1e7c93526141d40ba969bdc5bbdfd013932aaf1e644c66db66ff008e0"
        example_hash_02_Abcbot = "1fc59a86915eca78dbe0f90c7e0ee3fac6f7e5160c26a04330bf3858f7e5c1f2"
        example_hash_03_Godlua = "f18de35790254753dffc272d4e5e35b221185f2e300f25a75f636077c1ecc173"
        example_hash_04_LaplaceClipper = "f341ad891d445c745f10b4861a5c273abf7a38a0bd85168e7e6528e6b5c0141d"
        example_hash_05_Lockbit = "70cb1a8cb4259b72b704e81349c2ad5ac60cd1254a810ef68757f8c9409e3ea6"
        example_hash_06_NedDnLoader = "0fe796e1b7db725115a7de7ee8a56540f838305356b5de2f24de0883300e2c23"
        example_hash_07_OlympicDestroyer = "edb1ff2521fb4bf748111f92786d260d40407a2e8463dcd24bb09f908ee13eb9"
        example_hash_08_Mozi = "2d2239acd852e43952bcb14fcdc7485fd804b54df241c077750f5447b55354b7"
        example_hash_09_SBZ = "fbe103fac45abe4e3638055a3cac5e7009166f626cf2d3049fb46f3b53c1057f"
        example_hash_10_Wannacry = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
        example_hash_11_Rex = "9070f56651f44ec722e17df67b8a954888e387a8f2574594c80937d0f39c471a"
        example_hash_12_Xaynnalc = "9070f56651f44ec722e17df67b8a954888e387a8f2574594c80937d0f39c471a"

        DaysofYARA = "11/100"
    strings:
        $sbox = {
            63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
            ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
            b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
            04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
            09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
            53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
            d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
            51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
            cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
            60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
            e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
            e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
            ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
            70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
            e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
            8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
        }
        $reverse_sbox = {
            52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb
            7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb
            54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e
            08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25
            72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92
            6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84
            90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06
            d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b
            3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73
            96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e
            47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b
            fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4
            1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f
            60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef
            a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61
            17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d
        }
    condition:
        any of them
}
