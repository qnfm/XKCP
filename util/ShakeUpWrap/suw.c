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
#include <string.h>

static file_read_result_t get_file_size(const char *filepath, uint64_t *file_size) {
    struct stat st;

    if (filepath == NULL || file_size == NULL) {
        return FILE_READ_ERROR_NULL_POINTER;
    }

    if (stat(filepath, &st) != 0) {
        return FILE_READ_ERROR_FILE_NOT_FOUND;
    }

    if (st.st_size < 0) {
        return FILE_READ_ERROR_INVALID_PATH;
    }

    *file_size = (uint64_t)st.st_size;

    return FILE_READ_SUCCESS;
}

static uint8_t* safe_malloc(uint64_t size) {
    if (size == 0 || size > SIZE_MAX) {
        return NULL;
    }

    uint8_t *ptr = malloc((size_t)size);
    if (ptr == NULL) {
        return NULL;
    }

    memset(ptr, 0, (size_t)size);

    return ptr;
}

file_read_result_t read_large_file(const char *filepath, file_buffer_t *buffer) {
    FILE *file = NULL;
    uint64_t file_size = 0;
    uint64_t bytes_read_total = 0;
    uint64_t chunk_size = 0;
    size_t bytes_read_chunk = 0;
    file_read_result_t result = FILE_READ_SUCCESS;

    if (filepath == NULL || buffer == NULL) {
        return FILE_READ_ERROR_NULL_POINTER;
    }

    buffer->filepath = (char*)filepath;
    buffer->filename = NULL;
    buffer->data = NULL;
    buffer->size = 0;
    buffer->is_valid = 0;

    result = get_file_size(filepath, &file_size);
    if (result != FILE_READ_SUCCESS) {
        return result;
    }

    file = fopen(filepath, "rb");
    if (file == NULL) {
        return FILE_READ_ERROR_FILE_NOT_FOUND;
    }

    buffer->data = safe_malloc(file_size);
    if (buffer->data == NULL) {
        fclose(file);
        return FILE_READ_ERROR_MEMORY_ALLOCATION;
    }

    while (bytes_read_total < file_size) {
        uint64_t remaining = file_size - bytes_read_total;
        chunk_size = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;

        if (chunk_size > SIZE_MAX) {
            result = FILE_READ_ERROR_SIZE_OVERFLOW;
            goto cleanup;
        }

        bytes_read_chunk = fread(buffer->data + bytes_read_total, 1,
                                (size_t)chunk_size, file);

        if (bytes_read_chunk == 0) {
            if (ferror(file)) {
                result = FILE_READ_ERROR_READ_FAILED;
                goto cleanup;
            }
            if (bytes_read_total < file_size) {
                result = FILE_READ_ERROR_READ_FAILED;
                goto cleanup;
            }
            break;
        }

        bytes_read_total += bytes_read_chunk;

        if (bytes_read_total < bytes_read_chunk) {
            result = FILE_READ_ERROR_SIZE_OVERFLOW;
            goto cleanup;
        }
    }

    if (bytes_read_total != file_size) {
        result = FILE_READ_ERROR_READ_FAILED;
        goto cleanup;
    }

    buffer->size = file_size;
    buffer->is_valid = 1;
    fclose(file);

    buffer->filename = basename((char*)filepath);
    return FILE_READ_SUCCESS;

cleanup:
    if (file != NULL) {
        fclose(file);
    }
    if (buffer->data != NULL) {
        free(buffer->data);
        buffer->data = NULL;
    }
    buffer->size = 0;
    buffer->is_valid = 0;

    return result;
}

file_read_result_t dump_buffer_to_file(const file_buffer_t *buffer) {
    FILE *output_file = NULL;
    uint64_t bytes_written_total = 0;
    uint64_t chunk_size = 0;
    size_t bytes_written_chunk = 0;
    file_read_result_t result = FILE_READ_SUCCESS;

    if (buffer == NULL || buffer->filepath == NULL) {
        return FILE_READ_ERROR_NULL_POINTER;
    }

    if (!buffer->is_valid || buffer->data == NULL || buffer->size == 0) {
        return FILE_READ_ERROR_INVALID_PATH;
    }

    output_file = fopen(buffer->filepath, "wb");
    if (output_file == NULL) {
        return FILE_READ_ERROR_FILE_NOT_FOUND;
    }

    printf("Dumping buffer to: %s\n", buffer->filepath);
    printf("Writing %llu bytes (%.2f GB)...\n",
           (unsigned long long)buffer->size,
           (double)buffer->size / (1024.0 * 1024.0 * 1024.0));

    while (bytes_written_total < buffer->size) {
        uint64_t remaining = buffer->size - bytes_written_total;
        chunk_size = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;

        if (chunk_size > SIZE_MAX) {
            result = FILE_READ_ERROR_SIZE_OVERFLOW;
            goto cleanup;
        }

        bytes_written_chunk = fwrite(buffer->data + bytes_written_total, 1,
                                    (size_t)chunk_size, output_file);

        if (bytes_written_chunk == 0) {
            if (ferror(output_file)) {
                result = FILE_READ_ERROR_READ_FAILED; /* Reuse for write error */
                goto cleanup;
            }
            result = FILE_READ_ERROR_READ_FAILED;
            goto cleanup;
        }

        if (bytes_written_chunk != (size_t)chunk_size) {
            result = FILE_READ_ERROR_READ_FAILED;
            goto cleanup;
        }

        bytes_written_total += bytes_written_chunk;

        if (bytes_written_total < bytes_written_chunk) {
            result = FILE_READ_ERROR_SIZE_OVERFLOW;
            goto cleanup;
        }

        if (buffer->size > (10ULL * 1024ULL * 1024ULL * 1024ULL)) { /* > 10GB */
            double progress = (double)bytes_written_total / (double)buffer->size * 100.0;
            if (((bytes_written_total / CHUNK_SIZE) % 16) == 0) { /* Every 1GB */
                printf("Progress: %.1f%% (%.2f GB written)\n", progress,
                       (double)bytes_written_total / (1024.0 * 1024.0 * 1024.0));
            }
        }
    }

    if (bytes_written_total != buffer->size) {
        result = FILE_READ_ERROR_READ_FAILED;
        goto cleanup;
    }

    if (fflush(output_file) != 0) {
        result = FILE_READ_ERROR_READ_FAILED;
        goto cleanup;
    }

    printf("Successfully dumped %llu bytes to %s\n",
           (unsigned long long)bytes_written_total, buffer->filepath);

    fclose(output_file);
    return FILE_READ_SUCCESS;

cleanup:
    if (output_file != NULL) {
        fclose(output_file);
    }

    return result;
}

const char* get_error_message(file_read_result_t error_code) {
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
        case FILE_READ_ERROR_READ_FAILED:
            return "File read operation failed";
        case FILE_READ_ERROR_SIZE_OVERFLOW:
            return "File size causes arithmetic overflow";
        default:
            return "Unknown error";
    }
}

int encrypt(file_buffer_t *buf){
    KeccakWidth1600_DWrapInstance dww;
    const unsigned int c = 512;
    unsigned int    rho     = (1600 - c - 64) /8;
    unsigned int    taglen  = c / 8;
    uint8_t         k[64] = {};
    uint8_t         *C = safe_malloc(buf->size + taglen);
    if(getentropy(k, 64) != 0){
        printf("Fail to get entropy\n");
    }

    char Kpath[200] = {};
    strcpy(Kpath, buf->filepath);
    strcat(Kpath, ".key");
    FILE *kf= fopen(Kpath, "wb");
    if (kf) {
        if(fwrite(k, 1, 64, kf) != 64){
            return FILE_READ_ERROR_READ_FAILED;
        }
        fclose(kf);
    }

    SHAKE_Wrap_Initialize(&dww, k, sizeof(k), taglen, rho, c);
    SHAKE_Wrap_Wrap(&dww, C, buf->filename, strlen(buf->filename), buf->data, buf->size);

    file_buffer_t buf_out;
    buf_out.data = C;
    buf_out.size = buf->size + taglen;
    buf_out.is_valid = 1;

    char Cpath[200] = {};
    strcpy(Cpath, buf->filepath);
    strcat(Cpath, ".Suw");
    buf_out.filepath = Cpath;
    buf_out.filename = basename(Cpath);

    dump_buffer_to_file(&buf_out);
    free(buf->data);
    return FILE_READ_SUCCESS;
}

int decrypt(file_buffer_t *buf){
    KeccakWidth1600_DWrapInstance dwu;
    const unsigned int c = 512;
    unsigned int    rho     = (1600 - c - 64) /8;
    unsigned int    taglen  = c / 8;
    uint8_t         k[64] = {};
    uint8_t         *P = safe_malloc(buf->size - taglen);

    char Kpath[200] = {};
    strncpy(Kpath, buf->filepath, strlen(buf->filepath) + 1 - sizeof(".Suw"));
    strcat(Kpath, ".key");

    FILE *kf= fopen(Kpath, "rb");
    if (kf) {
        if(fread(k, 1, 64, kf) != 64){
            return FILE_READ_ERROR_READ_FAILED;
        }
        fclose(kf);
    }
    memset(Kpath, 0, 200);
    strncpy(Kpath, buf->filename, strlen(buf->filename) + 1 - sizeof(".Suw"));

    SHAKE_Wrap_Initialize(&dwu, k, sizeof(k), taglen, rho, c);
    SHAKE_Wrap_Unwrap(&dwu, P, Kpath, strlen(Kpath), buf->data, buf->size);

    file_buffer_t buf_out;
    buf_out.data = P;
    buf_out.size = buf->size - taglen;
    buf_out.is_valid = 1;

    memset(Kpath, 0, 200);
    strncpy(Kpath, buf->filepath, strlen(buf->filepath) + 1 - sizeof(".Suw"));
    buf_out.filepath = Kpath;
    buf_out.filename = basename(Kpath);

    dump_buffer_to_file(&buf_out);
    free(buf->data);
    return FILE_READ_SUCCESS;
}
#endif /* XKCP_has_ShakingUpAE */
