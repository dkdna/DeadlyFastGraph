## DeadlyFastGraph

This is a WebKit JIT challenge I created for InCTFi 2021. This was my first attempt writing a browser exploitation challenge, and it went pretty well!

### Setup & Build instructions

If you want to try out the challenge yourself, you have the following options:

+ Get the challenge handout files from [here](Handout/DFGHandout.zip), in this case you'll probably need to use my deployment setup and [Dockerfile](Server/Dockerfile)
+ To build WebKit yourself using the challenge patch, follow the following steps (you don't necessarily need the handout if you do this):

```sh
git clone https://github.com/WebKit/WebKit.git
cd WebKit
git checkout c40e806df2c49dac3049825cf48251a230296c6e
patch -p1 < dfg_debug.patch
Tools/Scripts/build-webkit --jsc-only --debug
cd WebKitBuild/Debug/bin

./jsc --useConcurrentJIT=false
```

You can find `dfg_debug.patch` [here](Admin/dfg_debug.patch)

### Short Writeup

The bug is a removal of a CheckStructure Node in DFG's Constant Folding Phase, and allows for an arbitrary type confusion, with the restriction that only one vulnerable JITed function can be used and the type confusion can only be triggered on one object. Check out the detailed, and hopefully beginner-friendly writeup [here](writeup.md) or on my [blog](https://d4rk-kn1gh7.github.io/InCTFi21-DeadlyFastGraph/)!

Also, feel free to ping me anytime on [twitter](https://twitter.com/_d4rkkn1gh7) if you have any questions regarding the challenge, I'll be happy to help you out!
