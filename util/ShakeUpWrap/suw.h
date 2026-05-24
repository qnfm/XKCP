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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <libgen.h>

#define CHUNK_SIZE (64ULL * 1024ULL * 1024ULL)                /* 64MB chunks */

typedef enum {
    ENTROPY_READ_FAILED,
    FILE_READ_SUCCESS,
    FILE_READ_ERROR_NULL_POINTER,
    FILE_READ_ERROR_INVALID_PATH,
    FILE_READ_ERROR_FILE_NOT_FOUND,
    FILE_READ_ERROR_FILE_TOO_SMALL,
    FILE_READ_ERROR_FILE_TOO_LARGE,
    FILE_READ_ERROR_MEMORY_ALLOCATION,
    FILE_ERROR_READ_FAILED,
    FILE_ERROR_WRITE_FAILED,
    FILE_ERROR_SIZE_OVERFLOW
} file_result_t;

const char* get_error_message(file_result_t error_code);

int encrypt(const char *path);
int decrypt(const char *path);
