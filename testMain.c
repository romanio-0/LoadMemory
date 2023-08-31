#include <stdio.h>

#include "LoadMemory.h"


int RunFromMemory(LPSTR file) {
    FILE *fp;
    BYTE *data = NULL;
    long size;
    size_t read;
    int result = -1;

    HMODULEMEMORY handle;

    fp = fopen(file, "rb");
    if (fp == NULL) {
        goto exit;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    if (size <= 0){
        goto exit;
    }

    data = (BYTE*) malloc(size);
    if(data == NULL){
        goto exit;
    }

    fseek(fp, 0, SEEK_SET);
    read = fread(data, 1, size, fp);
    if(read != (size_t) (size)){
        goto exit;
    }

    fclose(fp);

    handle = LoadLibraryFromMemory(data, size);
    if (handle == NULL) {
        goto exit;
    }

    result = CallEntryPointFromMemory(handle);
    if (result < 0) {
        printf("Could not execute entry point: %d\n", result);
    }
    FreeLibraryFromMemory(handle);

    exit:
    free(data);
    return result;
}

int main(int argc, char *argv[]){
    if (argc < 2)
        return RunFromMemory("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");

    return RunFromMemory(argv[1]);
}