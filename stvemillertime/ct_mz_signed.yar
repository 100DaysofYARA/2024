// #100daysofYARA
// day 2
// stvemillertime
// this size check ruleset is meant to help measure samples in a large corpus
// do simple checks on numbers, or run at command line with some bash to print out a histogram
// something like this

/*
yara -r ~/ct_pe_signed.yar ~/W11-FS/ | awk  '{print $1}' | sort | uniq -c |  awk  '{line = sprintf("%*s", ($1*(0.001)), ""); gsub(/ /, "*", line);print $2,$1,line}' 
head_pe_signed 26460 **************************
head_pe_unsigned 40717 ****************************************
*/

import "pe"
rule head_pe_signed { condition: pe.is_pe and pe.number_of_signatures == 0}
rule head_pe_unsigned { condition: pe.is_pe and pe.number_of_signatures != 0}