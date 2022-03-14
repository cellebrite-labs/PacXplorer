# PacXplorer
PacXplorer is an IDA plugin that adds XREFs between virtual functions and their call sites.  
This is accomplished by leveraging PAC codes in ARM64e binaries.
## Installation
1. install [ida-nentode](https://github.com/williballenthin/ida-netnode) somewhere IDA can import it
2. clone the repository and symlink `~/.idapro/plugins/pacxploer.py` to `pacxplorer.py` in the cloned repo
## Usage

### Preliminary Analysis
1. open an IDB and make sure autoanalysis has finished  
1.1. *KernelCache only:* make sure to run [ida_kernelcache](https://gitlab.cellebrite.srl/srl/ios/ida_kernelcache). This defines the `` `vtable for'`` symbols
2. from the menu select `Edit -> Plugins -> PacXplorer -> Analyse IDB`  
2.2. if asked, point PacXplorer to the original input binary file that created the IDB
    * this will only happen if the original PAC codes are not present in the IDB and the input binary can't be located automatically
3. done!

### Continuous Use
**TL;DR**

`⌘-x` or `Right Click -> Jump to PAC XREFs` at suitable locations will open a selection window

**From call site to virtual function**
1. place the cursor on a `MOVK` instruction near the call site to a virtual function (marked with a comment).
2. press the hotkey or activate the menu entry
3. a list of possible virtual methods called will open
4. if the same virtual function is called from several vtables, the `class` column will show `<multiple classes>` instead of a class name
    * `Right click -> PAC: toggle unique function names` toggles this grouping

**From virtual function to call site**
1. place the cursors either on a vtable entry or at the start of a virtual function
2. press the hotkey or activate the menu entry
3. a list of possible call sites will open

![](pacxplorer.gif)

## Principals of Operation
PAC codes sign pointers with a _key_ and a _context_.  
[LLVM ABI](https://github.com/apple/llvm-project/blob/apple/master/clang/docs/PointerAuthentication.rst#c-virtual-functions) specifies that the *context* of vtable entries is a mix between the *entry's address* and a *hash* of the function prototype.

Consider the following vtable at address `0x00000001 abcdef00`:  


| offset | method | hash |
| :----: | :---: | :---: |
| `0` | `foo()` | `0x1234` |
| `8` | `bar()` | `0x9876` |

The formula for calculating the context is:
```python
addr_part = (addr_of_vtable + offset_of_method) & 0x0000ffffffffffff
hash_part = (hash & 0xffff) << 48
context   =  addr_part | hash_part
```
Hence when calling `bar()`, the context will be: `0x98760001 abcdef08`.

Out of these factors, the *offset* of the method and the *hash* are known at compile time, but the actual *address of the vtable* is only known at runtime, through the `this` ptr (heck, this is the whole purpose of vtables to begin with).

Therefore, a typical (simplified) code snippet might look as follows:
```
LDR     X8, [X0]            ; load vtable address
LDRA    X9, [X8,#0x18]!     ; X8 = vtbl + offset
MOVK    X8, #0x68DA,LSL#48  ; set the hash 
BLRAA   X9, X8              ; virtual call
```
PacXplorer looks for similar `MOVK` instructions in all of the defined functions and analyses the code leading up to them, noting the *offset* in the table and the *hash value*, and constructs *PAC tuple mappings* of `{(offset, hash): address of call}`

On the other hand, PacXplorer iterates over all of the defined vtables, which it finds using symbol names.  
In the binary, each vtable contains *tagged pointers*, which will have been untagged by IDA. The pointer tags [embed](https://github.com/Synacktiv-contrib/kernelcache-laundering/blob/master/ios12_kernel_cache_helper.py) the hash values that are used for PAC.  
PacXplorer looks for the original pointer tags, which will have either been preserved in IDA's *patched bytes* window, or by opening the actual original binary. Using that, it creates the same *PAC tuple* for each virtual call, and construct a mapping of `{(offset, hash): entry in vtable}`.

At runtime, a simple matching of these two mappings is performed.

 ## Q&A
**Q: Why are there several virtual methods in the XREFs window?**  
**A:** This is the *inherent ambiguity* which is an intrinsic limitation of this method.  
For every class inheritance tree, when calling a virtual method that's present in the parent class and overloaded in some of the children, there is no knowing at compile time which overloaded version will actually get called.  
Obviously only what's known at compile time can be statically analysed.

**Q: Why use a special window and not add the XREFs to the regular XREF list?**  
**A:** Due to the inherent ambiguity of which virtual function is called, I decided not to add (potentially many) bogus XREFs to the regular list, but keep them separated.

**Q: Could there be false positives?**  
**A:** Yes. Besides the inherent ambiguity, there could also be cases where two functions in unrelated vtables generate the same (offset, hash) tuple.  
When trying out using the hash value alone (disregarding the offset in the vtable), I've encountered many such false positives.
Using the combination of (offset, hash) I'm yet to observe any such false positives.

**Q: Why is the XREF from the `MOVK` instruction and not the `BLRAA` call?**  
**A:** I've encountered instances of several virtual calls using the same BLRAA.  
Think of a function that selects a command handler with a switch-case, and all the cases jump to the same exit node that performs the call.

**Q: Great stuff, I want to work with you!**  
**A:** Uhh, that's not really a question but thanks! [click here](https://www.cellebrite.com/en/about/careers/positions/?comeet_cat=israel&comeet_pos=0B.613&comeet_all=all&rd) (Remote talent welcome)
 
## Limitations
1. Works only on ARM64e binaries that conform to [the ABI](https://github.com/apple/llvm-project/blob/apple/master/clang/docs/PointerAuthentication.rst#c-virtual-functions)
2. Vtable symbols need to be present in the binary (`` `vtable for'``). In the case of the Kernel, [ida_kernelcache](https://github.com/bazad/ida_kernelcache) needs to have been run. Note that the official version doesn't support recent Kernels, but forks exist.   
3. If the tagged pointers haven't been preserved in the IDB, the original binary is needed for the analysis stage (but not afterwards)
4. Hexrays support WIP

## Meta
Authored by Ouri Lipner of Cellebrite Security Research Labs. \
Currently maintained by Omer Porzecanski of Cellebrite Security Research Labs. \
Developed and tested for IDA 7.5 - 7.7 on OS X, iOS 12.x - 15.4 beta

