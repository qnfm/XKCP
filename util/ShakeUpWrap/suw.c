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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

typedef struct {
    FILE *fp;
    char *tmp_path;
    const char *final_path;
    int should_close;
    int committed;
} suw_output_t;

const char *suw_result_message(suw_result_t result)
{
    switch (result) {
    case SUW_OK:
        return "Success";

    case SUW_ERR_INVALID_ARGUMENT:
        return "Invalid argument";
    case SUW_ERR_MISSING_MODE:
        return "Missing required mode: specify -e or -d";
    case SUW_ERR_MULTIPLE_MODES:
        return "Invalid mode: specify exactly one of -e or -d";
    case SUW_ERR_MISSING_KEY_PATH:
        return "Missing required key path: -k KEYFILE";
    case SUW_ERR_UNEXPECTED_POSITIONAL_ARGUMENT:
        return "Unexpected positional argument";

    case SUW_ERR_KEY_ALREADY_EXISTS:
        return "Key file already exists";
    case SUW_ERR_KEY_NOT_FOUND:
        return "Key file does not exist";
    case SUW_ERR_KEY_OPEN_FAILED:
        return "Failed to open key file";
    case SUW_ERR_KEY_READ_FAILED:
        return "Failed to read key file";
    case SUW_ERR_KEY_WRITE_FAILED:
        return "Failed to write key file";
    case SUW_ERR_KEY_INVALID_SIZE:
        return "Invalid key file size";

    case SUW_ERR_INPUT_READ_FAILED:
        return "Failed to read input";
    case SUW_ERR_OUTPUT_OPEN_FAILED:
        return "Failed to open output file";
    case SUW_ERR_OUTPUT_ALREADY_EXISTS:
        return "Output file already exists";
    case SUW_ERR_OUTPUT_WRITE_FAILED:
        return "Failed to write output";
    case SUW_ERR_OUTPUT_CLOSE_FAILED:
        return "Failed to close output file";
    case SUW_ERR_OUTPUT_RENAME_FAILED:
        return "Failed to rename temporary output file";

    case SUW_ERR_MEMORY_ALLOCATION_FAILED:
        return "Memory allocation failed";
    case SUW_ERR_ENTROPY_FAILED:
        return "Failed to generate key material";

    case SUW_ERR_INVALID_CIPHERTEXT:
        return "Invalid ciphertext";
    case SUW_ERR_AUTHENTICATION_FAILED:
        return "Authentication failed";
    case SUW_ERR_UNEXPECTED_EOF:
        return "Unexpected end of input";

    case SUW_ERR_INTERNAL:
    default:
        return "Internal error";
    }
}

static void secure_clear(void *ptr, size_t len)
{
    if (ptr == NULL) {
        return;
    }

#if defined(__STDC_LIB_EXT1__)
    (void)memset_s(ptr, len, 0, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;

    while (len-- != 0) {
        *p++ = 0;
    }
#endif
}

static void store_u64_le(uint8_t out[8], uint64_t x)
{
    out[0] = (uint8_t)(x);
    out[1] = (uint8_t)(x >> 8);
    out[2] = (uint8_t)(x >> 16);
    out[3] = (uint8_t)(x >> 24);
    out[4] = (uint8_t)(x >> 32);
    out[5] = (uint8_t)(x >> 40);
    out[6] = (uint8_t)(x >> 48);
    out[7] = (uint8_t)(x >> 56);
}

static void make_chunk_aad(uint8_t aad[SUW_AAD_SIZE],
                           uint64_t chunk_index,
                           uint8_t final_flag)
{
    memset(aad, 0, SUW_AAD_SIZE);
    store_u64_le(aad + 0, chunk_index);
    aad[8] = final_flag;
}

static suw_result_t write_all_fd(int fd, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return SUW_ERR_KEY_WRITE_FAILED;
        }

        if (n == 0) {
            return SUW_ERR_KEY_WRITE_FAILED;
        }

        buf += (size_t)n;
        len -= (size_t)n;
    }

    return SUW_OK;
}

static suw_result_t read_exact_fd(int fd, uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = read(fd, buf, len);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return SUW_ERR_KEY_READ_FAILED;
        }

        if (n == 0) {
            return SUW_ERR_KEY_INVALID_SIZE;
        }

        buf += (size_t)n;
        len -= (size_t)n;
    }

    return SUW_OK;
}

static suw_result_t write_all_file(FILE *out, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        size_t written = fwrite(buf, 1, len, out);

        if (written == 0) {
            return SUW_ERR_OUTPUT_WRITE_FAILED;
        }

        buf += written;
        len -= written;
    }

    return SUW_OK;
}

/*
 * Fill a buffer unless EOF is reached.
 *
 * hit_eof is set when fewer than len bytes were read because the stream ended.
 * For regular files and pipes, this prevents accidental short reads from being
 * treated as chunk boundaries.
 */
static suw_result_t read_full_or_eof(FILE *input,
                                     uint8_t *buf,
                                     size_t len,
                                     size_t *bytes_read,
                                     int *hit_eof)
{
    size_t total = 0;

    while (total < len) {
        size_t n = fread(buf + total, 1, len - total, input);

        if (n > 0) {
            total += n;
            continue;
        }

        if (ferror(input)) {
            return SUW_ERR_INPUT_READ_FAILED;
        }

        if (feof(input)) {
            break;
        }
    }

    *bytes_read = total;
    *hit_eof = total < len;

    return SUW_OK;
}

#define SUW_ASYNC_READ_SLOTS 3U

typedef struct {
    uint8_t *buf;
    size_t len;
    int hit_eof;
    int state; /* 0 = empty, 1 = ready, 2 = owned by consumer */
    uint64_t seq;
} suw_async_read_slot_t;

typedef struct {
    FILE *input;
    size_t chunk_size;
    suw_async_read_slot_t slots[SUW_ASYNC_READ_SLOTS];
    uint64_t next_fill_seq;
    uint64_t next_drain_seq;
    int stop;
    int done;
    int started;
    suw_result_t result;
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t can_fill;
    pthread_cond_t can_drain;
} suw_async_reader_t;

static int async_reader_has_empty_slot(const suw_async_reader_t *reader)
{
    size_t i;

    for (i = 0; i < SUW_ASYNC_READ_SLOTS; i++) {
        if (reader->slots[i].state == 0) {
            return 1;
        }
    }

    return 0;
}

static suw_async_read_slot_t *async_reader_find_empty_slot(suw_async_reader_t *reader)
{
    size_t i;

    for (i = 0; i < SUW_ASYNC_READ_SLOTS; i++) {
        if (reader->slots[i].state == 0) {
            return &reader->slots[i];
        }
    }

    return NULL;
}

static suw_async_read_slot_t *async_reader_find_ready_slot(suw_async_reader_t *reader)
{
    size_t i;

    for (i = 0; i < SUW_ASYNC_READ_SLOTS; i++) {
        if (reader->slots[i].state == 1 &&
            reader->slots[i].seq == reader->next_drain_seq) {
            return &reader->slots[i];
        }
    }

    return NULL;
}

static void *async_reader_thread_main(void *arg)
{
    suw_async_reader_t *reader = (suw_async_reader_t *)arg;

    while (1) {
        suw_async_read_slot_t *slot;
        size_t len = 0;
        int hit_eof = 0;
        suw_result_t result;

        pthread_mutex_lock(&reader->mutex);
        while (!reader->stop && !async_reader_has_empty_slot(reader)) {
            pthread_cond_wait(&reader->can_fill, &reader->mutex);
        }

        if (reader->stop) {
            pthread_mutex_unlock(&reader->mutex);
            break;
        }

        slot = async_reader_find_empty_slot(reader);
        if (slot == NULL) {
            pthread_mutex_unlock(&reader->mutex);
            continue;
        }
        slot->state = 2;
        pthread_mutex_unlock(&reader->mutex);

        result = read_full_or_eof(reader->input,
                                  slot->buf,
                                  reader->chunk_size,
                                  &len,
                                  &hit_eof);

        pthread_mutex_lock(&reader->mutex);
        if (reader->stop) {
            slot->state = 0;
            pthread_cond_signal(&reader->can_fill);
            pthread_mutex_unlock(&reader->mutex);
            break;
        }

        if (result != SUW_OK) {
            reader->result = result;
            reader->done = 1;
            slot->state = 0;
            pthread_cond_broadcast(&reader->can_drain);
            pthread_mutex_unlock(&reader->mutex);
            break;
        }

        slot->len = len;
        slot->hit_eof = hit_eof;
        slot->seq = reader->next_fill_seq++;
        slot->state = 1;

        if (hit_eof) {
            reader->done = 1;
        }

        pthread_cond_broadcast(&reader->can_drain);
        pthread_mutex_unlock(&reader->mutex);

        if (hit_eof) {
            break;
        }
    }

    return NULL;
}

static suw_result_t async_reader_init(suw_async_reader_t *reader,
                                      FILE *input,
                                      size_t chunk_size)
{
    size_t i;
    int mutex_ready = 0;
    int can_fill_ready = 0;
    int can_drain_ready = 0;

    if (reader == NULL || input == NULL || chunk_size == 0) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    memset(reader, 0, sizeof(*reader));
    reader->input = input;
    reader->chunk_size = chunk_size;
    reader->result = SUW_OK;

    for (i = 0; i < SUW_ASYNC_READ_SLOTS; i++) {
        reader->slots[i].buf = malloc(chunk_size);
        if (reader->slots[i].buf == NULL) {
            goto fail;
        }
    }

    if (pthread_mutex_init(&reader->mutex, NULL) != 0) {
        goto fail;
    }
    mutex_ready = 1;

    if (pthread_cond_init(&reader->can_fill, NULL) != 0) {
        goto fail;
    }
    can_fill_ready = 1;

    if (pthread_cond_init(&reader->can_drain, NULL) != 0) {
        goto fail;
    }
    can_drain_ready = 1;

    if (pthread_create(&reader->thread, NULL, async_reader_thread_main, reader) != 0) {
        goto fail;
    }
    reader->started = 1;

    return SUW_OK;

fail:
    if (can_drain_ready) {
        pthread_cond_destroy(&reader->can_drain);
    }
    if (can_fill_ready) {
        pthread_cond_destroy(&reader->can_fill);
    }
    if (mutex_ready) {
        pthread_mutex_destroy(&reader->mutex);
    }
    for (i = 0; i < SUW_ASYNC_READ_SLOTS; i++) {
        free(reader->slots[i].buf);
        reader->slots[i].buf = NULL;
    }

    return SUW_ERR_MEMORY_ALLOCATION_FAILED;
}

static suw_result_t async_reader_next(suw_async_reader_t *reader,
                                      suw_async_read_slot_t **slot)
{
    suw_async_read_slot_t *ready;

    if (reader == NULL || slot == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    *slot = NULL;

    pthread_mutex_lock(&reader->mutex);
    while ((ready = async_reader_find_ready_slot(reader)) == NULL &&
           !reader->done) {
        pthread_cond_wait(&reader->can_drain, &reader->mutex);
    }

    if (ready != NULL) {
        ready->state = 2;
        reader->next_drain_seq++;
        *slot = ready;
        pthread_mutex_unlock(&reader->mutex);
        return SUW_OK;
    }

    if (reader->result != SUW_OK) {
        suw_result_t result = reader->result;
        pthread_mutex_unlock(&reader->mutex);
        return result;
    }

    pthread_mutex_unlock(&reader->mutex);
    return SUW_ERR_INTERNAL;
}

static void async_reader_release(suw_async_reader_t *reader,
                                 suw_async_read_slot_t *slot)
{
    if (reader == NULL || slot == NULL) {
        return;
    }

    pthread_mutex_lock(&reader->mutex);
    slot->state = 0;
    pthread_cond_signal(&reader->can_fill);
    pthread_mutex_unlock(&reader->mutex);
}

static void async_reader_destroy(suw_async_reader_t *reader)
{
    size_t i;

    if (reader == NULL) {
        return;
    }

    pthread_mutex_lock(&reader->mutex);
    reader->stop = 1;
    pthread_cond_broadcast(&reader->can_fill);
    pthread_cond_broadcast(&reader->can_drain);
    pthread_mutex_unlock(&reader->mutex);

    if (reader->started) {
        pthread_join(reader->thread, NULL);
        reader->started = 0;
    }

    pthread_cond_destroy(&reader->can_drain);
    pthread_cond_destroy(&reader->can_fill);
    pthread_mutex_destroy(&reader->mutex);

    for (i = 0; i < SUW_ASYNC_READ_SLOTS; i++) {
        secure_clear(reader->slots[i].buf, reader->chunk_size);
        free(reader->slots[i].buf);
        reader->slots[i].buf = NULL;
    }
}

static suw_result_t check_key_does_not_exist(const char *key_path)
{
    if (key_path == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    if (access(key_path, F_OK) == 0) {
        return SUW_ERR_KEY_ALREADY_EXISTS;
    }

    if (errno != ENOENT) {
        return SUW_ERR_KEY_OPEN_FAILED;
    }

    return SUW_OK;
}

static suw_result_t create_and_write_key(const char *key_path, uint8_t key[SUW_KEY_SIZE])
{
    if (key_path == NULL || key == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    if (getentropy(key, SUW_KEY_SIZE) != 0) {
        return SUW_ERR_ENTROPY_FAILED;
    }

    int fd = open(key_path,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                  S_IRUSR | S_IWUSR);
    if (fd < 0) {
        if (errno == EEXIST) {
            return SUW_ERR_KEY_ALREADY_EXISTS;
        }
        return SUW_ERR_KEY_OPEN_FAILED;
    }

    suw_result_t result = write_all_fd(fd, key, SUW_KEY_SIZE);

    if (close(fd) != 0 && result == SUW_OK) {
        result = SUW_ERR_KEY_WRITE_FAILED;
    }

    return result;
}

static suw_result_t read_key(const char *key_path, uint8_t key[SUW_KEY_SIZE])
{
    if (key_path == NULL || key == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    int fd = open(key_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            return SUW_ERR_KEY_NOT_FOUND;
        }
        return SUW_ERR_KEY_OPEN_FAILED;
    }

    suw_result_t result = read_exact_fd(fd, key, SUW_KEY_SIZE);

    if (result == SUW_OK) {
        uint8_t extra;
        ssize_t n;

        do {
            n = read(fd, &extra, 1);
        } while (n < 0 && errno == EINTR);

        if (n < 0) {
            result = SUW_ERR_KEY_READ_FAILED;
        } else if (n != 0) {
            result = SUW_ERR_KEY_INVALID_SIZE;
        }
    }

    if (close(fd) != 0 && result == SUW_OK) {
        result = SUW_ERR_KEY_READ_FAILED;
    }

    return result;
}

static suw_result_t make_tmp_path(const char *output_path, char **tmp_path)
{
    int needed;

    if (output_path == NULL || tmp_path == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    needed = snprintf(NULL, 0, "%s.tmp.%ld", output_path, (long)getpid());
    if (needed < 0) {
        return SUW_ERR_INTERNAL;
    }

    *tmp_path = malloc((size_t)needed + 1);
    if (*tmp_path == NULL) {
        return SUW_ERR_MEMORY_ALLOCATION_FAILED;
    }

    snprintf(*tmp_path, (size_t)needed + 1, "%s.tmp.%ld", output_path, (long)getpid());

    return SUW_OK;
}

static suw_result_t open_output(const char *output_path, suw_output_t *out)
{
    if (out == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));

    if (output_path == NULL) {
        out->fp = stdout;
        out->should_close = 0;
        return SUW_OK;
    }

    if (access(output_path, F_OK) == 0) {
        return SUW_ERR_OUTPUT_ALREADY_EXISTS;
    }

    if (errno != ENOENT) {
        return SUW_ERR_OUTPUT_OPEN_FAILED;
    }

    suw_result_t result = make_tmp_path(output_path, &out->tmp_path);
    if (result != SUW_OK) {
        return result;
    }

    int fd = open(out->tmp_path,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        free(out->tmp_path);
        out->tmp_path = NULL;

        if (errno == EEXIST) {
            return SUW_ERR_OUTPUT_ALREADY_EXISTS;
        }

        return SUW_ERR_OUTPUT_OPEN_FAILED;
    }

    out->fp = fdopen(fd, "wb");
    if (out->fp == NULL) {
        close(fd);
        unlink(out->tmp_path);
        free(out->tmp_path);
        out->tmp_path = NULL;
        return SUW_ERR_OUTPUT_OPEN_FAILED;
    }

    out->final_path = output_path;
    out->should_close = 1;

    return SUW_OK;
}

static suw_result_t commit_output(suw_output_t *out)
{
    if (out == NULL || out->fp == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    if (fflush(out->fp) != 0) {
        return SUW_ERR_OUTPUT_WRITE_FAILED;
    }

    if (out->should_close) {
        if (fclose(out->fp) != 0) {
            out->fp = NULL;
            return SUW_ERR_OUTPUT_CLOSE_FAILED;
        }

        out->fp = NULL;

        if (rename(out->tmp_path, out->final_path) != 0) {
            unlink(out->tmp_path);
            free(out->tmp_path);
            out->tmp_path = NULL;
            return SUW_ERR_OUTPUT_RENAME_FAILED;
        }

        out->committed = 1;
    }

    free(out->tmp_path);
    out->tmp_path = NULL;

    return SUW_OK;
}

static void abort_output(suw_output_t *out)
{
    if (out == NULL) {
        return;
    }

    if (out->fp != NULL && out->should_close) {
        fclose(out->fp);
        out->fp = NULL;
    }

    if (!out->committed && out->tmp_path != NULL) {
        unlink(out->tmp_path);
    }

    free(out->tmp_path);
    out->tmp_path = NULL;
}

suw_result_t encrypt_stream(FILE *input, const char *output_path, const char *key_path)
{
    if (input == NULL || key_path == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    suw_result_t result = SUW_OK;
    uint8_t key[SUW_KEY_SIZE] = {0};
    uint8_t aad[SUW_AAD_SIZE];

    suw_output_t output;

    result = check_key_does_not_exist(key_path);
    if (result != SUW_OK) {
        return result;
    }

    result = open_output(output_path, &output);
    if (result != SUW_OK) {
        return result;
    }

    suw_async_reader_t reader;
    suw_async_read_slot_t *cur = NULL;
    uint8_t *C = malloc(SUW_CHUNK_SIZE + SUW_TAGLEN);
    int reader_initialized = 0;

    if (C == NULL) {
        free(C);
        abort_output(&output);
        return SUW_ERR_MEMORY_ALLOCATION_FAILED;
    }

    result = async_reader_init(&reader, input, SUW_CHUNK_SIZE);
    if (result != SUW_OK) {
        free(C);
        abort_output(&output);
        return result;
    }
    reader_initialized = 1;

    result = create_and_write_key(key_path, key);
    if (result != SUW_OK) {
        goto done;
    }

    KeccakWidth1600_DWrapInstance dww;
    SHAKE_Wrap_Initialize(&dww, key, sizeof(key), SUW_TAGLEN, SUW_RHO, SUW_CAPACITY);

    uint64_t chunk_index = 0;

    size_t cur_len = 0;
    int cur_eof = 0;

    result = async_reader_next(&reader, &cur);
    if (result != SUW_OK) {
        goto done;
    }
    cur_len = cur->len;
    cur_eof = cur->hit_eof;

    /*
     * Empty plaintext: emit exactly one empty final chunk.
     *
     * This is the only accepted empty-final-chunk encoding. For non-empty
     * plaintext whose size is exactly a multiple of SUW_CHUNK_SIZE, the last
     * full chunk is marked final.
     */
    if (cur_len == 0 && cur_eof) {
        make_chunk_aad(aad, chunk_index, SUW_FINAL_TRUE);

        SHAKE_Wrap_Wrap(&dww,
                        C,
                        aad,
                        sizeof(aad),
                        cur->buf,
                        0);

        result = write_all_file(output.fp, C, SUW_TAGLEN);
        async_reader_release(&reader, cur);
        cur = NULL;
        goto done;
    }

    while (1) {
        suw_async_read_slot_t *next = NULL;
        size_t next_len = 0;
        int next_eof = 0;

        result = async_reader_next(&reader, &next);
        if (result != SUW_OK) {
            break;
        }

        next_len = next->len;
        next_eof = next->hit_eof;

        if (next_len == 0 && next_eof) {
            make_chunk_aad(aad, chunk_index, SUW_FINAL_TRUE);

            SHAKE_Wrap_Wrap(&dww,
                            C,
                            aad,
                            sizeof(aad),
                            cur->buf,
                            cur_len);

            result = write_all_file(output.fp, C, cur_len + SUW_TAGLEN);
            async_reader_release(&reader, cur);
            cur = NULL;
            async_reader_release(&reader, next);
            break;
        }

        make_chunk_aad(aad, chunk_index, SUW_FINAL_FALSE);

        SHAKE_Wrap_Wrap(&dww,
                        C,
                        aad,
                        sizeof(aad),
                        cur->buf,
                        cur_len);

        result = write_all_file(output.fp, C, cur_len + SUW_TAGLEN);
        async_reader_release(&reader, cur);
        cur = NULL;
        if (result != SUW_OK) {
            async_reader_release(&reader, next);
            break;
        }

        chunk_index++;
        cur = next;
        cur_len = next_len;
        cur_eof = next_eof;
        (void)cur_eof;
    }

done:
    if (result == SUW_OK) {
        result = commit_output(&output);
    } else {
        abort_output(&output);
    }

    if (cur != NULL) {
        async_reader_release(&reader, cur);
        cur = NULL;
    }
    if (reader_initialized) {
        async_reader_destroy(&reader);
    }
    secure_clear(C, SUW_CHUNK_SIZE + SUW_TAGLEN);
    secure_clear(key, sizeof(key));
    secure_clear(aad, sizeof(aad));

    free(C);

    return result;
}

suw_result_t decrypt_stream(FILE *input, const char *output_path, const char *key_path)
{
    if (input == NULL || key_path == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    suw_result_t result = SUW_OK;
    uint8_t key[SUW_KEY_SIZE] = {0};
    uint8_t aad[SUW_AAD_SIZE];

    suw_output_t output;

    result = read_key(key_path, key);
    if (result != SUW_OK) {
        secure_clear(key, sizeof(key));
        return result;
    }

    result = open_output(output_path, &output);
    if (result != SUW_OK) {
        secure_clear(key, sizeof(key));
        return result;
    }

    uint8_t *C0 = malloc(SUW_CHUNK_SIZE + SUW_TAGLEN);
    uint8_t *C1 = malloc(SUW_CHUNK_SIZE + SUW_TAGLEN);
    uint8_t *P = malloc(SUW_CHUNK_SIZE);

    if (C0 == NULL || C1 == NULL || P == NULL) {
        free(C0);
        free(C1);
        free(P);
        abort_output(&output);
        secure_clear(key, sizeof(key));
        return SUW_ERR_MEMORY_ALLOCATION_FAILED;
    }

    KeccakWidth1600_DWrapInstance dwu;
    SHAKE_Wrap_Initialize(&dwu, key, sizeof(key), SUW_TAGLEN, SUW_RHO, SUW_CAPACITY);

    uint64_t chunk_index = 0;

    size_t cur_len = 0;
    int cur_eof = 0;

    result = read_full_or_eof(input,
                              C0,
                              SUW_CHUNK_SIZE + SUW_TAGLEN,
                              &cur_len,
                              &cur_eof);
    if (result != SUW_OK) {
        goto done;
    }

    if (cur_len == 0 && cur_eof) {
        result = SUW_ERR_INVALID_CIPHERTEXT;
        goto done;
    }

    while (1) {
        size_t next_len = 0;
        int next_eof = 0;
        uint8_t final_flag = SUW_FINAL_FALSE;

        result = read_full_or_eof(input,
                                  C1,
                                  SUW_CHUNK_SIZE + SUW_TAGLEN,
                                  &next_len,
                                  &next_eof);
        if (result != SUW_OK) {
            break;
        }

        if (next_len == 0 && next_eof) {
            final_flag = SUW_FINAL_TRUE;
        }

        if (cur_len < SUW_TAGLEN) {
            result = SUW_ERR_INVALID_CIPHERTEXT;
            break;
        }

        if (final_flag == SUW_FINAL_FALSE &&
            cur_len != SUW_CHUNK_SIZE + SUW_TAGLEN) {
            result = SUW_ERR_INVALID_CIPHERTEXT;
            break;
        }

        if (final_flag == SUW_FINAL_TRUE &&
            cur_len > SUW_CHUNK_SIZE + SUW_TAGLEN) {
            result = SUW_ERR_INVALID_CIPHERTEXT;
            break;
        }

        /*
         * Enforce the age-style canonical rule:
         * an empty final chunk is valid only for empty plaintext.
         */
        if (final_flag == SUW_FINAL_TRUE &&
            cur_len == SUW_TAGLEN &&
            chunk_index != 0) {
            result = SUW_ERR_INVALID_CIPHERTEXT;
            break;
        }

        make_chunk_aad(aad, chunk_index, final_flag);

        if (SHAKE_Wrap_Unwrap(&dwu,
                              P,
                              aad,
                              sizeof(aad),
                              C0,
                              cur_len) != 0) {
            result = SUW_ERR_AUTHENTICATION_FAILED;
            break;
        }

        result = write_all_file(output.fp, P, cur_len - SUW_TAGLEN);
        if (result != SUW_OK) {
            break;
        }

        if (final_flag == SUW_FINAL_TRUE) {
            result = SUW_OK;
            break;
        }

        chunk_index++;

        {
            uint8_t *tmp = C0;
            C0 = C1;
            C1 = tmp;
        }

        cur_len = next_len;
        (void)next_eof;
    }

done:
    if (result == SUW_OK) {
        result = commit_output(&output);
    } else {
        abort_output(&output);
    }

    secure_clear(C0, SUW_CHUNK_SIZE + SUW_TAGLEN);
    secure_clear(C1, SUW_CHUNK_SIZE + SUW_TAGLEN);
    secure_clear(P, SUW_CHUNK_SIZE);
    secure_clear(key, sizeof(key));
    secure_clear(aad, sizeof(aad));

    free(C0);
    free(C1);
    free(P);

    return result;
}

#endif /* XKCP_has_ShakingUpAE */
