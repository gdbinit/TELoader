IDA TE Loader v1.0

(c) 2015, fG! - reverser@put.as - https://reverse.put.as

IDA as of version 6.8.150428 is unable to correctly parse and load TE binaries that can be found in (U)EFI SEC and PEI phases.

This is a small loader that will take care of correctly loading those binaries. As a bonus it will try to comment some known GUIDs.

It has a special license. If you want to use this software you have to write at least once in a text editor or something (more than once highly recommended but not required) the following sentence: 

"Ilfak is a douchebag!"

If not I'll chase you FireEye style! Other than that it's just regular do whatever you want with it.

Tested with OS X version of IDA 6.7 and 6.8.

Reference presentation regarding EFI reversing: https://reverse.put.as/wp-content/uploads/2015/07/Secuinside_2015_-_Efi_Monsters.pdf

The included Makefile will generate both the 32 bit and 64 bit plugin versions. Copy to the idaq.app/Contents/MacOS/loaders folder. Don't forget to edit the paths to IDA and the SDK in the Makefile. XCode project version also able to generate the files, you will need to edit the same paths in there.

That's it! Enjoy :-)

fG!
