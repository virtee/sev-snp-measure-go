# sev-snp-measure-go

This tool is a direct port of [virtee/sev-snp-measure](https://github.com/virtee/sev-snp-measure).
Motivation to write this port is to integrate measurement calculation into Go tools.

The following limitations apply to this port atm:
- only supports SNP
- only measures the initial firmware

What this port does that [virtee/sev-snp-measure](https://github.com/virtee/sev-snp-measure) doesn't do:
- parse OVMF metadata from a OVMF binary. This can be used (together with OVMFHash) to calculate measurements without having access to the binary.

If you need more features or find a bug please open an issue.
For features that [virtee/sev-snp-measure](https://github.com/virtee/sev-snp-measure) provides, addition should be quick.

# Used by

This tool was originally developed for [Constellation](https://github.com/edgelesssys/constellation) to verify launch measurements on AWS's SNP instances.
