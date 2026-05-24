/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include "config.h"
#ifdef XKCP_has_ShakingUpAE

#include "suw.h"
#include "ShakingUpAE.h"
#include <assert.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

const char* get_error_message(file_result_t error_code) {
    switch (error_code) {
        case FILE_READ_SUCCESS:
            return "Success";
        case FILE_READ_ERROR_NULL_POINTER:
            return "Null pointer provided";
        case FILE_READ_ERROR_INVALID_PATH:
            return "Invalid file path";
        case FILE_READ_ERROR_FILE_NOT_FOUND:
            return "File not found or cannot be opened";
        case FILE_READ_ERROR_FILE_TOO_SMALL:
            return "File size is smaller than 100GB";
        case FILE_READ_ERROR_FILE_TOO_LARGE:
            return "File size exceeds 999GB limit";
        case FILE_READ_ERROR_MEMORY_ALLOCATION:
            return "Memory allocation failed";
        case FILE_ERROR_READ_FAILED:
            return "File read operation failed";
        case FILE_ERROR_SIZE_OVERFLOW:
            return "File size causes arithmetic overflow";
        default:
            return "Unknown error";
    }
}

int encrypt(const char *path){
    const unsigned int c = 512;
    unsigned int    rho     = (1600 - c - 64) /8;
    unsigned int    taglen  = c / 8;
    uint8_t         k[64] = {};
    file_result_t err = FILE_READ_SUCCESS;
    if(getentropy(k, 64) != 0){
        perror("Fail to get entropy\n");
        return ENTROPY_READ_FAILED;
    }

    const char * name = basename(path);
    char Kpath[200] = {};
    strcpy(Kpath, name);
    strcat(Kpath, ".key");
    FILE *kf= fopen(Kpath, "ab");
    if (kf) {
        if(fwrite(k, 1, 64, kf) != 64) return FILE_ERROR_WRITE_FAILED;
        fclose(kf);
    }

    char Cpath[200] = {};
    strcpy(Cpath, name);
    strcat(Cpath, ".Suw");

    FILE *input_file = fopen(path, "rb");
    if (!input_file) {
        perror("Error opening input file");
        return EXIT_FAILURE;
    }

    FILE *output_file = fopen(Cpath, "ab");
    if (!output_file) {
          perror("Error opening output file");
          fclose(input_file);
          return EXIT_FAILURE;
    }
    KeccakWidth1600_DWrapInstance dww;
    SHAKE_Wrap_Initialize( &dww, k, sizeof(k), taglen, rho, c );
    uint64_t bytes_read;
    uint64_t total_processed = 0;

    uint8_t *P = malloc(CHUNK_SIZE);
    uint8_t *C = malloc(CHUNK_SIZE + taglen);

    while ((bytes_read = fread(P, 1, CHUNK_SIZE, input_file)) > 0) {
        SHAKE_Wrap_Wrap(&dww, C, name, strlen(name), P, bytes_read);

        size_t bytes_written = fwrite(C, 1, bytes_read + taglen, output_file);
        if (bytes_written != bytes_read + taglen) {
            perror("Error writing to output file");
            err = FILE_ERROR_WRITE_FAILED;
            break;
        }

        total_processed += bytes_read;
        if (((total_processed / CHUNK_SIZE) % 16) == 0) { /* Every 1GB */
            printf("Progress: %.2f GB written\n", (double)total_processed/ (1024.0 * 1024.0 * 1024.0));
        }
    }

    free(P);
    free(C);
    fclose(input_file);
    fclose(output_file);

    return err;
}

int decrypt(const char *path){
    const unsigned int c = 512;
    unsigned int    rho     = (1600 - c - 64) /8;
    unsigned int    taglen  = c / 8;
    uint8_t         k[64] = {};
    file_result_t err = FILE_READ_SUCCESS;

    FILE *input_file = fopen(path, "rb");
    if (!input_file) {
        perror("Error opening input file");
        return EXIT_FAILURE;
    }

    const char * Cname = basename(path);
    uint8_t *name = malloc(strlen(path) - 4 + 1);
    strncpy(name, Cname, strlen(Cname) + 1 - sizeof(".Suw"));

    char Kpath[200] = {};
    strncpy(Kpath, name, strlen(name));
    strcat(Kpath, ".key");

    FILE *kf= fopen(Kpath, "rb");
    if (kf) {
        if(fread(k, 1, 64, kf) != 64){
            fclose(input_file);
            fclose(kf);
            return FILE_ERROR_READ_FAILED;
        }
        fclose(kf);
    }

    memset(Kpath, 0, 200);
    strncpy(Kpath, path, strlen(path) + 1 - sizeof(".Suw"));

    FILE *output_file = fopen(Kpath, "wb");
    if (!output_file) {
        perror("Error opening output file");
        fclose(input_file);
        return EXIT_FAILURE;
    }

    KeccakWidth1600_DWrapInstance dwu;
    SHAKE_Wrap_Initialize( &dwu, k, sizeof(k), taglen, rho, c );
    uint64_t bytes_read;
    uint64_t total_processed = 0;

    uint8_t *P = malloc(CHUNK_SIZE);
    uint8_t *C = malloc(CHUNK_SIZE + taglen);

    while ((bytes_read = fread(C, 1, CHUNK_SIZE + taglen, input_file)) > 0) {
        SHAKE_Wrap_Unwrap(&dwu, P, name, strlen(name), C, bytes_read);

        size_t bytes_written = fwrite(P, 1, bytes_read - taglen, output_file);
        if (bytes_written != bytes_read - taglen) {
            perror("Error writing to output file");
            err = FILE_ERROR_WRITE_FAILED;
            break;
        }

        total_processed += bytes_read;
        if (((total_processed / CHUNK_SIZE) % 16) == 0) { /* Every 1GB */
            printf("Progress: %.2f GB written\n", (double)total_processed/ (1024.0 * 1024.0 * 1024.0));
        }
    }

    free(name);
    free(P);
    free(C);
    fclose(input_file);
    fclose(output_file);

    return err;
}
#endif /* XKCP_has_ShakingUpAE */
