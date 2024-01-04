// #100daysofYARA
// day 2
// stvemillertime
// this size check ruleset is meant to help measure samples in a large corpus
// run at command line with some bash to print out a histogram
// something like this
/*
yara -r ~/ct_size_bands_mz.yar ~/W11-FS/ | awk  '{print $1}' | sort | uniq -c |  awk  '{line = sprintf("%*s", ($1*(0.001)), ""); gsub(/ /, "*", line);print $2,$1,line}'
head_mz_a_small_lt_5kb 2771 **
head_mz_b_small_5kb_10kb 2403 **
head_mz_c_med_10kb_100kb 36016 ************************************
head_mz_d_med_100kb_1mb 21090 *********************
head_mz_e_med_1mb_10mb 4325 ****
head_mz_f_large_gt_10mb 279 
*/


rule head_mz_a_small_lt_5kb { condition: uint16be(0) == 0x4d5a 
    and filesize < 5KB }
rule head_mz_b_small_5kb_10kb { condition: uint16be(0) == 0x4d5a 
    and filesize > 5KB and filesize < 10KB }
rule head_mz_c_med_10kb_100kb { condition: uint16be(0) == 0x4d5a 
    and filesize > 10KB and filesize < 100KB }
rule head_mz_d_med_100kb_1mb { condition: uint16be(0) == 0x4d5a 
    and filesize > 100KB and filesize < 1000KB }
rule head_mz_e_med_1mb_10mb { condition: uint16be(0) == 0x4d5a 
    and filesize > 1000KB and filesize < 10000KB }
rule head_mz_f_large_gt_10mb { condition: uint16be(0) == 0x4d5a 
    and filesize > 10000KB }
