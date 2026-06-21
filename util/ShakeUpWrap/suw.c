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
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <liburing.h>

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
 * Asynchronous chunk reader backed by Linux io_uring.
 *
 * This is the io_uring counterpart of the pthread-based reader: it prefetches
 * plaintext chunks ahead of the encryption loop so that disk reads overlap with
 * the SHAKE_Wrap computation, but it does so without a dedicated reader thread.
 * The main thread submits read requests to the kernel and harvests completions
 * on demand.
 *
 * Each slot is filled to exactly chunk_size bytes (issuing follow-up reads for
 * short reads) unless end of stream is reached first. As with read_full_or_eof,
 * the consumer is always handed an explicit zero-length EOF chunk to mark the
 * final boundary; reading past end of file naturally produces it.
 */

#define SUW_IO_READ_SLOTS 3U

typedef struct {
    uint8_t *buf;
    size_t   want;    /* target byte count for this chunk */
    size_t   filled;  /* bytes received so far */
    off_t    offset;  /* starting file offset (seekable inputs only) */
    uint64_t seq;     /* delivery order */
    int      eof;     /* a short or zero read was observed */
    int      ready;   /* fully filled or eof: available to the consumer */
    int      active;  /* a read request is currently in flight */
    int      in_use;  /* slot holds a scheduled or delivered chunk */
} suw_io_slot_t;

typedef struct {
    struct io_uring ring;
    int          ring_ready;
    int          fd;
    int          seekable;
    size_t       chunk_size;
    off_t        next_offset;     /* offset for the next scheduled chunk */
    uint64_t     next_fill_seq;   /* seq for the next scheduled chunk */
    uint64_t     next_drain_seq;  /* seq the consumer expects next */
    int          eof_scheduled;   /* a zero-length terminator has been produced */
    int          failed;
    suw_result_t result;
    suw_io_slot_t slots[SUW_IO_READ_SLOTS];
} suw_io_reader_t;

static int io_reader_count_active(const suw_io_reader_t *reader)
{
    size_t i;
    int active = 0;

    for (i = 0; i < SUW_IO_READ_SLOTS; i++) {
        if (reader->slots[i].active) {
            active++;
        }
    }

    return active;
}

static suw_result_t io_reader_submit_read(suw_io_reader_t *reader,
                                          suw_io_slot_t *slot)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&reader->ring);
    off_t offset;

    if (sqe == NULL) {
        return SUW_ERR_INTERNAL;
    }

    offset = reader->seekable ? (slot->offset + (off_t)slot->filled) : (off_t)-1;

    io_uring_prep_read(sqe,
                       reader->fd,
                       slot->buf + slot->filled,
                       (unsigned)(slot->want - slot->filled),
                       (__u64)offset);
    io_uring_sqe_set_data(sqe, slot);
    slot->active = 1;

    return SUW_OK;
}

/*
 * Assign free slots to upcoming chunks and submit their initial reads. For
 * non-seekable inputs (pipes) at most one read may be in flight at a time so
 * that bytes are delivered in order.
 */
static suw_result_t io_reader_schedule(suw_io_reader_t *reader)
{
    size_t i;
    int submitted = 0;

    for (i = 0; i < SUW_IO_READ_SLOTS; i++) {
        suw_io_slot_t *slot = &reader->slots[i];

        if (reader->eof_scheduled || reader->failed) {
            break;
        }
        if (slot->in_use) {
            continue;
        }
        if (!reader->seekable && io_reader_count_active(reader) > 0) {
            break;
        }

        slot->want = reader->chunk_size;
        slot->filled = 0;
        slot->offset = reader->next_offset;
        slot->seq = reader->next_fill_seq;
        slot->eof = 0;
        slot->ready = 0;
        slot->in_use = 1;

        reader->next_offset += (off_t)reader->chunk_size;
        reader->next_fill_seq++;

        suw_result_t r = io_reader_submit_read(reader, slot);
        if (r != SUW_OK) {
            reader->failed = 1;
            reader->result = r;
            return r;
        }
        submitted++;
    }

    if (submitted > 0) {
        int s = io_uring_submit(&reader->ring);
        if (s < 0) {
            reader->failed = 1;
            reader->result = SUW_ERR_INPUT_READ_FAILED;
            return reader->result;
        }
    }

    return SUW_OK;
}

static void io_reader_handle_completion(suw_io_reader_t *reader,
                                        suw_io_slot_t *slot,
                                        int res)
{
    slot->active = 0;

    if (res < 0) {
        if (res == -EINTR || res == -EAGAIN) {
            (void)io_reader_submit_read(reader, slot);
            (void)io_uring_submit(&reader->ring);
            return;
        }
        reader->failed = 1;
        reader->result = SUW_ERR_INPUT_READ_FAILED;
        return;
    }

    if (res == 0) {
        slot->eof = 1;
        slot->ready = 1;
        if (slot->filled == 0) {
            reader->eof_scheduled = 1;
        }
        return;
    }

    slot->filled += (size_t)res;

    if (slot->filled >= slot->want) {
        slot->ready = 1;
        return;
    }

    /* Short read: keep filling this chunk. */
    (void)io_reader_submit_read(reader, slot);
    (void)io_uring_submit(&reader->ring);
}

/* Drain every completion currently available without blocking. */
static void io_reader_pump(suw_io_reader_t *reader)
{
    struct io_uring_cqe *cqe;

    while (io_uring_peek_cqe(&reader->ring, &cqe) == 0) {
        suw_io_slot_t *slot = io_uring_cqe_get_data(cqe);
        int res = cqe->res;

        io_uring_cqe_seen(&reader->ring, cqe);

        if (slot != NULL) {
            io_reader_handle_completion(reader, slot, res);
        }
    }
}

static suw_io_slot_t *io_reader_find_ready(suw_io_reader_t *reader)
{
    size_t i;

    for (i = 0; i < SUW_IO_READ_SLOTS; i++) {
        if (reader->slots[i].in_use &&
            reader->slots[i].ready &&
            reader->slots[i].seq == reader->next_drain_seq) {
            return &reader->slots[i];
        }
    }

    return NULL;
}

static suw_result_t io_reader_init(suw_io_reader_t *reader,
                                   int fd,
                                   size_t chunk_size)
{
    size_t i;
    off_t pos;

    if (reader == NULL || fd < 0 || chunk_size == 0) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    memset(reader, 0, sizeof(*reader));
    reader->fd = fd;
    reader->chunk_size = chunk_size;
    reader->result = SUW_OK;

    pos = lseek(fd, 0, SEEK_CUR);
    if (pos >= 0) {
        reader->seekable = 1;
        reader->next_offset = pos;
    } else {
        reader->seekable = 0;
        reader->next_offset = 0;
    }

    for (i = 0; i < SUW_IO_READ_SLOTS; i++) {
        reader->slots[i].buf = malloc(chunk_size);
        if (reader->slots[i].buf == NULL) {
            goto fail;
        }
    }

    if (io_uring_queue_init(SUW_IO_READ_SLOTS * 2U, &reader->ring, 0) != 0) {
        goto fail;
    }
    reader->ring_ready = 1;

    return SUW_OK;

fail:
    for (i = 0; i < SUW_IO_READ_SLOTS; i++) {
        free(reader->slots[i].buf);
        reader->slots[i].buf = NULL;
    }

    return SUW_ERR_MEMORY_ALLOCATION_FAILED;
}

/*
 * Deliver the next chunk in sequence. The returned slot stays owned by the
 * caller until io_reader_release() is called.
 */
static suw_result_t io_reader_next(suw_io_reader_t *reader,
                                   suw_io_slot_t **slot)
{
    if (reader == NULL || slot == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    *slot = NULL;

    while (1) {
        suw_io_slot_t *ready;
        struct io_uring_cqe *cqe;
        int r;

        suw_result_t sched = io_reader_schedule(reader);
        if (sched != SUW_OK) {
            return sched;
        }

        io_reader_pump(reader);

        if (reader->failed) {
            return reader->result;
        }

        ready = io_reader_find_ready(reader);
        if (ready != NULL) {
            reader->next_drain_seq++;
            *slot = ready;
            /*
             * Refill the pipeline before handing control back to the caller so
             * that a read for an upcoming chunk is in flight while the caller
             * encrypts this one. This is what lets reads overlap computation,
             * including on non-seekable inputs where only one read may be in
             * flight at a time.
             */
            (void)io_reader_schedule(reader);
            return SUW_OK;
        }

        if (io_reader_count_active(reader) == 0) {
            /* Nothing ready and nothing in flight: no data can arrive. */
            return SUW_ERR_INTERNAL;
        }

        r = io_uring_wait_cqe(&reader->ring, &cqe);
        if (r < 0) {
            if (r == -EINTR) {
                continue;
            }
            reader->failed = 1;
            reader->result = SUW_ERR_INPUT_READ_FAILED;
            return reader->result;
        }

        {
            suw_io_slot_t *done = io_uring_cqe_get_data(cqe);
            int res = cqe->res;

            io_uring_cqe_seen(&reader->ring, cqe);
            if (done != NULL) {
                io_reader_handle_completion(reader, done, res);
            }
        }
    }
}

static void io_reader_release(suw_io_reader_t *reader, suw_io_slot_t *slot)
{
    if (reader == NULL || slot == NULL) {
        return;
    }

    slot->in_use = 0;
    slot->ready = 0;
    slot->filled = 0;
    slot->eof = 0;

    (void)io_reader_schedule(reader);
}

static void io_reader_destroy(suw_io_reader_t *reader)
{
    size_t i;

    if (reader == NULL) {
        return;
    }

    if (reader->ring_ready) {
        /* Drain any outstanding reads before tearing the ring down. */
        while (io_reader_count_active(reader) > 0) {
            struct io_uring_cqe *cqe;

            if (io_uring_wait_cqe(&reader->ring, &cqe) < 0) {
                break;
            }

            {
                suw_io_slot_t *slot = io_uring_cqe_get_data(cqe);
                if (slot != NULL) {
                    slot->active = 0;
                }
            }
            io_uring_cqe_seen(&reader->ring, cqe);
        }

        io_uring_queue_exit(&reader->ring);
        reader->ring_ready = 0;
    }

    for (i = 0; i < SUW_IO_READ_SLOTS; i++) {
        if (reader->slots[i].buf != NULL) {
            secure_clear(reader->slots[i].buf, reader->chunk_size);
            free(reader->slots[i].buf);
            reader->slots[i].buf = NULL;
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

    suw_io_reader_t reader;
    suw_io_slot_t *cur = NULL;
    uint8_t *C = malloc(SUW_CHUNK_SIZE + SUW_TAGLEN);
    int reader_initialized = 0;

    if (C == NULL) {
        free(C);
        abort_output(&output);
        return SUW_ERR_MEMORY_ALLOCATION_FAILED;
    }

    result = io_reader_init(&reader, fileno(input), SUW_CHUNK_SIZE);
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

    result = io_reader_next(&reader, &cur);
    if (result != SUW_OK) {
        goto done;
    }
    cur_len = cur->filled;

    /*
     * Empty plaintext: emit exactly one empty final chunk.
     *
     * This is the only accepted empty-final-chunk encoding. For non-empty
     * plaintext whose size is exactly a multiple of SUW_CHUNK_SIZE, the last
     * full chunk is marked final.
     */
    if (cur_len == 0 && cur->eof) {
        make_chunk_aad(aad, chunk_index, SUW_FINAL_TRUE);

        SHAKE_Wrap_Wrap(&dww,
                        C,
                        aad,
                        sizeof(aad),
                        cur->buf,
                        0);

        result = write_all_file(output.fp, C, SUW_TAGLEN);
        io_reader_release(&reader, cur);
        cur = NULL;
        goto done;
    }

    while (1) {
        suw_io_slot_t *next = NULL;
        size_t next_len = 0;
        int next_eof = 0;

        result = io_reader_next(&reader, &next);
        if (result != SUW_OK) {
            break;
        }

        next_len = next->filled;
        next_eof = next->eof;

        if (next_len == 0 && next_eof) {
            make_chunk_aad(aad, chunk_index, SUW_FINAL_TRUE);

            SHAKE_Wrap_Wrap(&dww,
                            C,
                            aad,
                            sizeof(aad),
                            cur->buf,
                            cur_len);

            result = write_all_file(output.fp, C, cur_len + SUW_TAGLEN);
            io_reader_release(&reader, cur);
            cur = NULL;
            io_reader_release(&reader, next);
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
        io_reader_release(&reader, cur);
        cur = NULL;
        if (result != SUW_OK) {
            io_reader_release(&reader, next);
            break;
        }

        chunk_index++;
        cur = next;
        cur_len = next_len;
    }

done:
    if (result == SUW_OK) {
        result = commit_output(&output);
    } else {
        abort_output(&output);
    }

    if (cur != NULL) {
        io_reader_release(&reader, cur);
        cur = NULL;
    }
    if (reader_initialized) {
        io_reader_destroy(&reader);
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
