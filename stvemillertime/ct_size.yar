// #100daysofYARA
// day 1
// stvemillertime
// this size check ruleset is meant to help measure samples in a large corpus
// run at command line to some counting yara ~/ct_size.yar -r ~/corpusfolder/ | awk  '{print $1}' | sort | uniq -c

rule ct_size_gt0 { condition: filesize > 0 }