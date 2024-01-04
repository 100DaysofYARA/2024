// #100daysofYARA
// day 2
// stvemillertime
// this size check ruleset is meant to help measure samples in a large corpus
// run at command line with some bash to print out a histogram

/*
yara -r ~/ct_size_bands.yar ~/vx/x_apt/ | awk  '{print $1}' | sort | uniq -c |  awk  '{line = sprintf("%*s", ($1*(0.01)), ""); gsub(/ /, "*", line);print $2,$1,line}'  
ct_size_0_1kb 383 ***
ct_size_100kb_1000kb 16160 *****************************************************************************************************************************************************************
ct_size_100mb_1gb 37 
ct_size_10kb_100kb 8841 ****************************************************************************************
ct_size_10kb_1mb 103 *
ct_size_10mb_100mb 716 *******
ct_size_1kb_10kb 1449 **************
ct_size_1mb_10mb 7436 **************************************************************************
*/

rule ct_size_0_1kb { condition: filesize > 0 and filesize < 1000 }
rule ct_size_1kb_10kb { condition: filesize > 1KB and filesize < 10KB }
rule ct_size_10kb_100kb { condition: filesize > 10KB and filesize < 100KB }
rule ct_size_100kb_1000kb { condition: filesize > 100KB and filesize < 1000KB }
rule ct_size_10kb_1mb { condition: filesize > 1000KB and filesize < 1MB }
rule ct_size_1mb_10mb { condition: filesize > 1MB and filesize < 10MB }
rule ct_size_10mb_100mb { condition: filesize > 10MB and filesize < 100MB }
rule ct_size_100mb_1gb { condition: filesize > 100MB and filesize < 1000MB }
rule ct_size_1gb_plus { condition: filesize > 1000MB }