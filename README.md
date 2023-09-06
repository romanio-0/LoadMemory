# LoadMemory
This is a program for downloading an exe/dll file into memory without the participation of the Windows loader.
It is also possible to get a function from a dll file.

There is a __TestMain.c__ file for use, it implements an example of loading powershell

## Note:

The idea for writing was borrowed.
Some exe/dll files may not load.
___
## Main metods:

**-** **`HMODULEMEMORY LoadLibraryFromMemory(const void *data, size_t size)`** - the main function which loads the exe/dll file into memory.
#### param:
    const void *data - accepts a previously read exe/dll file to load it into memory.
    size_t size - you need to pass the size of the transferred data block.

    return HMODULEMEMORY - returns the hmodule of the uploaded file, or NULL on error.

**-** **`int CallEntryPointFromMemory(HMODULEMEMORY mod)`** - function that runs the downloaded exe file.
#### param:
    HMODULEMEMORY mod - принемает hmodule ранее загруженного в память файла функцией LoadLibraryFromMemory.

**-** **`void FreeLibraryFromMemory(HMODULEMEMORY)`** - unloads a previously loaded file from memory.
#### param:
    HMODULEMEMORY mod - принемает hmodule ранее загруженного в память файла функцией LoadLibraryFromMemory.

**-** **`FARPROC GetProcAddressFromMemory(HMODULEMEMORY, LPCSTR)`** - Get address of exported method.
#### param:
    HMODULEMEMORY mod - принемает hmodule ранее загруженного в память файла функцией LoadLibraryFromMemory.
    LPCSTR name - you need to rewrite the name of the desired function.
___