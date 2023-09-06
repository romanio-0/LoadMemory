/*
 * This is a program for downloading an exe/dll file into memory without the participation of the Windows loader.
 * It is also possible to get a function from a dll file.
 * *
 * There is a __TestMain.c__ file for use, it implements an example of loading powershell
 *
 * Note:
 * The idea for writing was borrowed.
 * Some exe/dll files may not load.
 */
#ifndef _LOAD_MEMORY_H_
#define _LOAD_MEMORY_H_

#include <windows.h>

typedef void *HMODULEMEMORY;

typedef void *HMODULECUSTOM;

#ifdef __cplusplus
extern "C" {
#endif

typedef LPVOID (*FCustomAlloc)(LPVOID, SIZE_T, DWORD, DWORD, void*);
typedef BOOL (*FCustomFree)(LPVOID, SIZE_T, DWORD, void*);
typedef HMODULECUSTOM (*FCustomLoadLibrary)(LPCSTR, void *);
typedef FARPROC (*FCustomGetProcAddress)(HMODULECUSTOM, LPCSTR, void *);
typedef void (*FCustomFreeLibrary)(HMODULECUSTOM, void *);

/*
 * Load exe/dll from memory location with the given size using Windows API
 * dependency resolvers.
 */
HMODULEMEMORY LoadLibraryFromMemory(const void *, size_t);

/*
 * Load exe/dll from memory location with the given size using custom
 * dependency resolvers.
 */
HMODULEMEMORY LoadLibraryFromMemoryEx(const void *, size_t,
                                      FCustomAlloc, FCustomFree,
                                      FCustomLoadLibrary, FCustomGetProcAddress,
                                      FCustomFreeLibrary, void *);

/*
 * Get address of exported method.
 * Supports loading by name and by ordinal value.
 */
FARPROC GetProcAddressFromMemory(HMODULEMEMORY, LPCSTR);

/*
 * Free loaded exe/dll.
 */
void FreeLibraryFromMemory(HMODULEMEMORY);

/*
 * Execute entry point (EXE only).
 *
 * Attention: after calling this function, as soon as the loaded Exe-file
 * completes its work, the process will end!
 *
 * Returns a negative value if the entry point could not be executed.
 */
int CallEntryPointFromMemory(HMODULEMEMORY);

// Support function

/*
 * This is a function that implements VirtualAlloc and is
 * used to call in LoadLibraryFromMemory
 */
LPVOID DefaultAllocFromMemory(LPVOID, SIZE_T, DWORD, DWORD, void *);

/*
 * This is a function that implements VirtualFree and is
 * used to call in LoadLibraryFromMemory
 */
BOOL DefaultFreeFromMemory(LPVOID, SIZE_T, DWORD, void *);

/*
 * This is a function that implements LoadLibraryA and is
 * used to call in LoadLibraryFromMemory
 */
HMODULECUSTOM DefaultLoadLibraryFromMemory(LPCSTR, void *);

/*
 * This is a function that implements GetProcAddress and is
 * used to call in LoadLibraryFromMemory
 */
FARPROC DefaultGetProcAddressFromMemory(HMODULECUSTOM, LPCSTR, void *);

/*
 * This is a function that implements FreeLibrary and is
 * used to call in LoadLibraryFromMemory
 */
void DefaultFreeLibraryFromMemory(HMODULECUSTOM, void *);

#ifdef __cplusplus
}
#endif

#endif  // _LOAD_MEMORY_H_
