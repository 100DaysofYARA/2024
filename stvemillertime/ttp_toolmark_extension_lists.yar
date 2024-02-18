import "pe"

rule ttp_toolmark_fileextensions_array_2 {
    meta:
        author = "stvemillertime"
        desc = "this looks for pes with lots of file extensions in a special format"
    strings:
        $a00 = /(\*|\;|\%)\.doc/ ascii
        $a01 = /(\*|\;|\%)\.docx/ ascii
        $a02 = /(\*|\;|\%)\.pdf/ ascii
        $a03 = /(\*|\;|\%)\.txt/ ascii
        $a04 = /(\*|\;|\%)\.zip/ ascii
        $a05 = /(\*|\;|\%)\.eml/ ascii
        $a06 = /(\*|\;|\%)\.rtf/ ascii
        $a07 = /(\*|\;|\%)\.xls/ ascii
        $a08 = /(\*|\;|\%)\.xlsx/ ascii
        $a09 = /(\*|\;|\%)\.ppt/ ascii
        $a10 = /(\*|\;|\%)\.pptx/ ascii
        $a12 = /(\*|\;|\%)\.cbz/ ascii
        $a13 = /(\*|\;|\%)\.rar/ ascii
        $a14 = /(\*|\;|\%)\.hwp/ ascii
        $a17 = /(\*|\;|\%)\.csproj/ ascii
        $a18 = /(\*|\;|\%)\.suo/ ascii
        $a19 = /(\*|\;|\%)\.pdb/ ascii
        $a20 = /(\*|\;|\%)\.resx/ ascii
        $a21 = /(\*|\;|\%)\.cpp/ ascii
        $a22 = /(\*|\;|\%)\.cls/ ascii
        $a23 = /(\*|\;|\%)\.vcxproj/ ascii
        $a24 = /(\*|\;|\%)\.idb/ ascii
        $a25 = /(\*|\;|\%)\.iso/ ascii
        $a26 = /(\*|\;|\%)\.sln/ ascii
    condition:  
        filesize < 15MB
        and uint16be(0) == 0x4d5a 
        and 4 of them
}