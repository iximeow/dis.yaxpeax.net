### `dis.yaxpeax.net`

this a rough translation of [yaxpeax-dis](https://github.com/iximeow/yaxpeax-dis), the CLI tool, to instead accept architectures and data to disassemble as an HTTP request. the package is then deployed to `dis.yaxpeax.net` as a [compute@edge](https://docs.fastly.com/products/compute-at-edge) application.

### usage
taken right from the application itself:
```
usage: `https://dis.yaxpeax.net/<arch>/<hex bytes>`
additionally, the ?q query parameter can be used to remove the address and
byte framing, printing only disassembled instructions.

<arch> may be any of the supported architectures:
x86_64, x86_32, x86_16, x86:64, x86:32, x86:16,
ia64, armv7, armv8, avr, mips, msp430, pic17, pic18,
m16c, 6502, lc87, {sh{,2,3,4},j2}[[+-]{be,mmu,fpu,f64,j2}]
```

disassemblers and their supported-ness are also listed in the [yaxpeax-arch](https://git.iximeow.net/yaxpeax-arch/about/) matrix.
