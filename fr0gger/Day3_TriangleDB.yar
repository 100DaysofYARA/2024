rule OperationTriangulation_TriangleDB
{
  meta:
    author = "Thomas Roccia | @fr0gger_"
    description = "100DaysOfYara | Match on implant TriangleDB"
    sample = "063db86f015fe99fdd821b251f14446d"
    source = "https://securelist.com/triangledb-triangulation-implant/110050/"
  strings:
    $s1 = "swapLpServerType"
    $s2 = "getBuildArchitecture"
    $s3 = "swapLpServerType"
    $s4 = "CRXBlank"
    $s5 = "CRXConfigureDBServer"
    $s6 = "CRXUpdateConfigInfo"
    $s7 = "CRXFetchMatchingRecords"

    $enc = "unmungeHexString"
    $macOs = "populateWithFieldsMacOSOnly"

    $macho = { CF FA ED FE }   // Little Endian 64

  condition:
   $macho at 0 and (3 of ($s*)) and ($enc or $macOs)
}