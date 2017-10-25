llvm-deobfuscator
=================

Performs the inverse operation of the control flow flattening pass performed by
LLVM-Obfuscator. *Warning*: not yet functional, is only able to reconstruct the original
control flow but does not yet patch the input file to reflect this.

Makes use of the BinaryNinja SSA form to determine all usages of the state variable. To
use, right click on the state variable and click "Deobfuscate (OLLVM)".  Note that the
instruction writing to the state variable is typically in the first basic block of the
function, and looks something like:

```asm
mov dword [rbp-0xf8], 0x962e7c4e
```

with minor variations in the large constant and variable offset.

For more information on llvm obfuscator itself, the [source][llvm-obfuscator] is an
obvious ground truth :)

[llvm-obfuscator]: https://github.com/obfuscator-llvm/obfuscator/tree/llvm-4.0/lib/Transforms/Obfuscation
