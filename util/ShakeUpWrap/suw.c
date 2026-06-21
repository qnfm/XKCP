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

/*
 * Parallel chunk processing.
 *
 * ShakingUpAE's DWrap is a stateful duplex: calling Wrap/Unwrap evolves the
 * instance, so the original streaming format chains every chunk into a single
 * sequence and is therefore strictly serial. This build instead treats each
 * chunk as an independent message: every chunk is wrapped from a *clone* of the
 * initial keyed instance, with the chunk index and final flag bound in the AAD.
 * Independent chunks can then be encrypted/decrypted concurrently on a pool of
 * worker threads. The AAD still binds ordering and finality, so truncation,
 * reordering and tampering remain detectable exactly as before.
 */

typedef struct {
    const KeccakWidth1600_DWrapInstance *base;
    uint8_t       *in;        /* plaintext (encrypt) or ciphertext+tag (decrypt) */
    size_t         in_len;
    uint8_t       *out;       /* ciphertext+tag (encrypt) or plaintext (decrypt) */
    size_t         out_len;
    uint64_t       chunk_index;
    uint8_t        final_flag;
    int            is_decrypt;
    int            auth_ok;    /* decrypt only: 1 if the tag verified */
} suw_chunk_job_t;

typedef struct {
    suw_chunk_job_t *jobs;
    size_t           start;
    size_t           end;
} suw_worker_arg_t;

static void suw_process_job(suw_chunk_job_t *j)
{
    KeccakWidth1600_DWrapInstance local;
    uint8_t aad[SUW_AAD_SIZE];

    SHAKE_Wrap_Clone(&local, j->base);
    make_chunk_aad(aad, j->chunk_index, j->final_flag);

    if (j->is_decrypt) {
        if (SHAKE_Wrap_Unwrap(&local, j->out, aad, sizeof(aad),
                              j->in, j->in_len) == 0) {
            j->auth_ok = 1;
            j->out_len = j->in_len - SUW_TAGLEN;
        } else {
            j->auth_ok = 0;
            j->out_len = 0;
        }
    } else {
        SHAKE_Wrap_Wrap(&local, j->out, aad, sizeof(aad), j->in, j->in_len);
        j->out_len = j->in_len + SUW_TAGLEN;
    }
}

static void *suw_worker_main(void *arg)
{
    suw_worker_arg_t *w = (suw_worker_arg_t *)arg;
    size_t i;

    for (i = w->start; i < w->end; i++) {
        suw_process_job(&w->jobs[i]);
    }

    return NULL;
}

static unsigned suw_num_threads(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);

    if (n < 1) {
        n = 1;
    }
    if (n > (long)SUW_MAX_THREADS) {
        n = (long)SUW_MAX_THREADS;
    }

    return (unsigned)n;
}

/* Process jobs[0..njobs) across up to nthreads worker threads, then return. */
static void suw_run_batch(suw_chunk_job_t *jobs, size_t njobs, unsigned nthreads)
{
    pthread_t        threads[SUW_MAX_THREADS];
    suw_worker_arg_t args[SUW_MAX_THREADS];
    int              created[SUW_MAX_THREADS];
    size_t           per, rem, start;
    unsigned         t;

    if (njobs == 0) {
        return;
    }

    if (nthreads < 1) {
        nthreads = 1;
    }
    if ((size_t)nthreads > njobs) {
        nthreads = (unsigned)njobs;
    }

    if (nthreads == 1) {
        suw_worker_arg_t a = { jobs, 0, njobs };
        suw_worker_main(&a);
        return;
    }

    per = njobs / nthreads;
    rem = njobs % nthreads;
    start = 0;

    for (t = 0; t < nthreads; t++) {
        size_t count = per + (t < rem ? 1u : 0u);

        args[t].jobs = jobs;
        args[t].start = start;
        args[t].end = start + count;
        start += count;

        if (pthread_create(&threads[t], NULL, suw_worker_main, &args[t]) == 0) {
            created[t] = 1;
        } else {
            /* Fall back to running this slice on the calling thread. */
            created[t] = 0;
            suw_worker_main(&args[t]);
        }
    }

    for (t = 0; t < nthreads; t++) {
        if (created[t]) {
            pthread_join(threads[t], NULL);
        }
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

    suw_output_t output;

    result = check_key_does_not_exist(key_path);
    if (result != SUW_OK) {
        return result;
    }

    result = open_output(output_path, &output);
    if (result != SUW_OK) {
        return result;
    }

    unsigned nthreads = suw_num_threads();
    size_t   width = nthreads;            /* chunks processed per batch */
    size_t   i;

    /* width + 1 input buffers (one extra for cross-batch read-ahead). */
    uint8_t **inbuf = calloc(width + 1, sizeof(*inbuf));
    uint8_t **outbuf = calloc(width, sizeof(*outbuf));
    suw_chunk_job_t *jobs = calloc(width, sizeof(*jobs));
    int alloc_ok = (inbuf != NULL && outbuf != NULL && jobs != NULL);

    if (alloc_ok) {
        for (i = 0; i < width + 1; i++) {
            inbuf[i] = malloc(SUW_CHUNK_SIZE);
            if (inbuf[i] == NULL) {
                alloc_ok = 0;
            }
        }
        for (i = 0; i < width; i++) {
            outbuf[i] = malloc(SUW_CHUNK_SIZE + SUW_TAGLEN);
            if (outbuf[i] == NULL) {
                alloc_ok = 0;
            }
        }
    }

    if (!alloc_ok) {
        result = SUW_ERR_MEMORY_ALLOCATION_FAILED;
        abort_output(&output);
        goto cleanup;
    }

    result = create_and_write_key(key_path, key);
    if (result != SUW_OK) {
        goto done;
    }

    KeccakWidth1600_DWrapInstance dww;
    SHAKE_Wrap_Initialize(&dww, key, sizeof(key), SUW_TAGLEN, SUW_RHO, SUW_CAPACITY);

    uint64_t chunk_index = 0;
    size_t   cur_len = 0;
    int      cur_eof = 0;

    result = read_full_or_eof(input, inbuf[0], SUW_CHUNK_SIZE, &cur_len, &cur_eof);
    if (result != SUW_OK) {
        goto done;
    }

    /*
     * Empty plaintext: emit exactly one empty final chunk. This is the only
     * accepted empty-final-chunk encoding.
     */
    if (cur_len == 0 && cur_eof) {
        jobs[0].base = &dww;
        jobs[0].in = inbuf[0];
        jobs[0].in_len = 0;
        jobs[0].out = outbuf[0];
        jobs[0].chunk_index = 0;
        jobs[0].final_flag = SUW_FINAL_TRUE;
        jobs[0].is_decrypt = 0;

        suw_process_job(&jobs[0]);
        result = write_all_file(output.fp, jobs[0].out, jobs[0].out_len);
        goto done;
    }

    int done_flag = 0;
    while (!done_flag) {
        size_t nb = 0;

        while (1) {
            size_t next_len = 0;
            int next_eof = 0;
            uint8_t final_flag;

            /* Read one chunk ahead to learn whether the current one is final. */
            result = read_full_or_eof(input, inbuf[nb + 1], SUW_CHUNK_SIZE,
                                      &next_len, &next_eof);
            if (result != SUW_OK) {
                goto done;
            }

            final_flag = (next_len == 0 && next_eof) ? SUW_FINAL_TRUE
                                                     : SUW_FINAL_FALSE;

            jobs[nb].base = &dww;
            jobs[nb].in = inbuf[nb];
            jobs[nb].in_len = cur_len;
            jobs[nb].out = outbuf[nb];
            jobs[nb].chunk_index = chunk_index++;
            jobs[nb].final_flag = final_flag;
            jobs[nb].is_decrypt = 0;
            nb++;

            if (final_flag == SUW_FINAL_TRUE) {
                done_flag = 1;
                break;
            }

            cur_len = next_len;       /* read-ahead chunk now sits in inbuf[nb] */
            if (nb == width) {
                break;                /* batch full; carry inbuf[width] below */
            }
        }

        suw_run_batch(jobs, nb, nthreads);

        for (i = 0; i < nb; i++) {
            result = write_all_file(output.fp, jobs[i].out, jobs[i].out_len);
            if (result != SUW_OK) {
                goto done;
            }
        }

        if (!done_flag) {
            uint8_t *tmp = inbuf[0];
            inbuf[0] = inbuf[width];
            inbuf[width] = tmp;
        }
    }

done:
    if (result == SUW_OK) {
        result = commit_output(&output);
    } else {
        abort_output(&output);
    }

cleanup:
    if (inbuf != NULL) {
        for (i = 0; i < width + 1; i++) {
            if (inbuf[i] != NULL) {
                secure_clear(inbuf[i], SUW_CHUNK_SIZE);
                free(inbuf[i]);
            }
        }
        free(inbuf);
    }
    if (outbuf != NULL) {
        for (i = 0; i < width; i++) {
            if (outbuf[i] != NULL) {
                secure_clear(outbuf[i], SUW_CHUNK_SIZE + SUW_TAGLEN);
                free(outbuf[i]);
            }
        }
        free(outbuf);
    }
    free(jobs);
    secure_clear(key, sizeof(key));

    return result;
}

suw_result_t decrypt_stream(FILE *input, const char *output_path, const char *key_path)
{
    if (input == NULL || key_path == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    suw_result_t result = SUW_OK;
    uint8_t key[SUW_KEY_SIZE] = {0};

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

    unsigned nthreads = suw_num_threads();
    size_t   width = nthreads;
    size_t   i;

    uint8_t **inbuf = calloc(width + 1, sizeof(*inbuf));
    uint8_t **outbuf = calloc(width, sizeof(*outbuf));
    suw_chunk_job_t *jobs = calloc(width, sizeof(*jobs));
    int alloc_ok = (inbuf != NULL && outbuf != NULL && jobs != NULL);

    if (alloc_ok) {
        for (i = 0; i < width + 1; i++) {
            inbuf[i] = malloc(SUW_CHUNK_SIZE + SUW_TAGLEN);
            if (inbuf[i] == NULL) {
                alloc_ok = 0;
            }
        }
        for (i = 0; i < width; i++) {
            outbuf[i] = malloc(SUW_CHUNK_SIZE);
            if (outbuf[i] == NULL) {
                alloc_ok = 0;
            }
        }
    }

    if (!alloc_ok) {
        result = SUW_ERR_MEMORY_ALLOCATION_FAILED;
        abort_output(&output);
        goto cleanup;
    }

    KeccakWidth1600_DWrapInstance dwu;
    SHAKE_Wrap_Initialize(&dwu, key, sizeof(key), SUW_TAGLEN, SUW_RHO, SUW_CAPACITY);

    uint64_t chunk_index = 0;
    size_t   cur_len = 0;
    int      cur_eof = 0;

    result = read_full_or_eof(input, inbuf[0], SUW_CHUNK_SIZE + SUW_TAGLEN,
                              &cur_len, &cur_eof);
    if (result != SUW_OK) {
        goto done;
    }

    if (cur_len == 0 && cur_eof) {
        result = SUW_ERR_INVALID_CIPHERTEXT;
        goto done;
    }

    int done_flag = 0;
    while (!done_flag) {
        size_t nb = 0;

        while (1) {
            size_t next_len = 0;
            int next_eof = 0;
            uint8_t final_flag;

            result = read_full_or_eof(input, inbuf[nb + 1],
                                      SUW_CHUNK_SIZE + SUW_TAGLEN,
                                      &next_len, &next_eof);
            if (result != SUW_OK) {
                goto done;
            }

            final_flag = (next_len == 0 && next_eof) ? SUW_FINAL_TRUE
                                                     : SUW_FINAL_FALSE;

            if (cur_len < SUW_TAGLEN) {
                result = SUW_ERR_INVALID_CIPHERTEXT;
                goto done;
            }
            if (final_flag == SUW_FINAL_FALSE &&
                cur_len != SUW_CHUNK_SIZE + SUW_TAGLEN) {
                result = SUW_ERR_INVALID_CIPHERTEXT;
                goto done;
            }
            if (final_flag == SUW_FINAL_TRUE &&
                cur_len > SUW_CHUNK_SIZE + SUW_TAGLEN) {
                result = SUW_ERR_INVALID_CIPHERTEXT;
                goto done;
            }
            /* An empty final chunk is valid only for empty plaintext. */
            if (final_flag == SUW_FINAL_TRUE &&
                cur_len == SUW_TAGLEN &&
                chunk_index != 0) {
                result = SUW_ERR_INVALID_CIPHERTEXT;
                goto done;
            }

            jobs[nb].base = &dwu;
            jobs[nb].in = inbuf[nb];
            jobs[nb].in_len = cur_len;
            jobs[nb].out = outbuf[nb];
            jobs[nb].chunk_index = chunk_index++;
            jobs[nb].final_flag = final_flag;
            jobs[nb].is_decrypt = 1;
            jobs[nb].auth_ok = 0;
            nb++;

            if (final_flag == SUW_FINAL_TRUE) {
                done_flag = 1;
                break;
            }

            cur_len = next_len;
            if (nb == width) {
                break;
            }
        }

        suw_run_batch(jobs, nb, nthreads);

        for (i = 0; i < nb; i++) {
            if (!jobs[i].auth_ok) {
                result = SUW_ERR_AUTHENTICATION_FAILED;
                goto done;
            }
        }

        for (i = 0; i < nb; i++) {
            result = write_all_file(output.fp, jobs[i].out, jobs[i].out_len);
            if (result != SUW_OK) {
                goto done;
            }
        }

        if (!done_flag) {
            uint8_t *tmp = inbuf[0];
            inbuf[0] = inbuf[width];
            inbuf[width] = tmp;
        }
    }

done:
    if (result == SUW_OK) {
        result = commit_output(&output);
    } else {
        abort_output(&output);
    }

cleanup:
    if (inbuf != NULL) {
        for (i = 0; i < width + 1; i++) {
            if (inbuf[i] != NULL) {
                secure_clear(inbuf[i], SUW_CHUNK_SIZE + SUW_TAGLEN);
                free(inbuf[i]);
            }
        }
        free(inbuf);
    }
    if (outbuf != NULL) {
        for (i = 0; i < width; i++) {
            if (outbuf[i] != NULL) {
                secure_clear(outbuf[i], SUW_CHUNK_SIZE);
                free(outbuf[i]);
            }
        }
        free(outbuf);
    }
    free(jobs);
    secure_clear(key, sizeof(key));

    return result;
}

#endif /* XKCP_has_ShakingUpAE */
