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
void testShakingUpAE(void);
#endif
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <libgen.h>
#define MAX_FILE_SIZE (1024ULL * 1024ULL * 1024ULL * 1024ULL)  /* 1TB */
#define MIN_FILE_SIZE (100ULL * 1024ULL * 1024ULL * 1024ULL)  /* 100GB */
#define CHUNK_SIZE (64ULL * 1024ULL * 1024ULL)                /* 64MB chunks */

typedef enum {
    FILE_READ_SUCCESS = 0,
    FILE_READ_ERROR_NULL_POINTER = -1,
    FILE_READ_ERROR_INVALID_PATH = -2,
    FILE_READ_ERROR_FILE_NOT_FOUND = -3,
    FILE_READ_ERROR_FILE_TOO_SMALL = -4,
    FILE_READ_ERROR_FILE_TOO_LARGE = -5,
    FILE_READ_ERROR_MEMORY_ALLOCATION = -6,
    FILE_READ_ERROR_READ_FAILED = -7,
    FILE_READ_ERROR_SIZE_OVERFLOW = -8
} file_read_result_t;

typedef struct {
    char    *filepath;
    char    *filename;
    uint8_t *data;
    uint64_t size;
    int is_valid;
} file_buffer_t;

file_read_result_t read_large_file(const char *filepath, file_buffer_t *buffer);

const char* get_error_message(file_read_result_t error_code);

file_read_result_t dump_buffer_to_file(const file_buffer_t *buffer);

static file_read_result_t get_file_size(const char *filepath, uint64_t *file_size);

int encrypt(file_buffer_t *buf);
int decrypt(file_buffer_t *buf);
