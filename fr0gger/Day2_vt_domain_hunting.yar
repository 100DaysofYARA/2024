import "vt"

rule OperationTriangulation_Domain_Hunting
{
  meta:
    author = "Thomas Roccia | @fr0gger_"
    description = "100DaysofYara - VT domain hunting for OperationTriangulation"
    source = "https://securelist.com/operation-triangulation/109842/"

  condition:
    vt.net.domain.raw == "addatamarket.net" or
    vt.net.domain.raw == "backuprabbit.com" or
    vt.net.domain.raw == "businessvideonews.com" or
    vt.net.domain.raw == "cloudsponcer.com" or
    vt.net.domain.raw == "datamarketplace.net" or
    vt.net.domain.raw == "mobilegamerstats.com" or
    vt.net.domain.raw == "snoweeanalytics.com" or
    vt.net.domain.raw == "tagclick-cdn.com" or
    vt.net.domain.raw == "topographyupdates.com" or
    vt.net.domain.raw == "unlimitedteacup.com" or
    vt.net.domain.raw == "virtuallaughing.com" or
    vt.net.domain.raw == "web-trackers.com" or
    vt.net.domain.raw == "growthtransport.com" or
    vt.net.domain.raw == "anstv.net" or
    vt.net.domain.raw == "ans7tv.net" and
    (
        vt.net.domain.communicating_file.new_for_domain or 
        vt.net.domain.communicating_file.new_for_vt
    )
}