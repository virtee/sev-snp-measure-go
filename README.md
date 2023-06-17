This tool is a direct port of [ibm/sev-snp-measure](https://github.com/IBM/sev-snp-measure).
Most of the code was translated using chatGPT.
Motivation to write this tool is to integrate measurement calculation into Go tools.

This port aims to only support SNP measurements.
It does not support including kernel/initrd into the measurement.
To add those features compare the code to the original tool.
