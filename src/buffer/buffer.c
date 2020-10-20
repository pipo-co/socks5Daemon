/**
 * buffer.c - buffer con acceso directo (útil para I/O) que mantiene
 *            mantiene puntero de lectura y de escritura.
 */
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "buffer.h"

inline void
buffer_reset(buffer *b) {
    b->read  = b->data;
    b->write = b->data;
}

void
buffer_init(buffer *b, const size_t n, uint8_t *data) {
    b->data = data;
    buffer_reset(b);
    b->limit = b->data + n;
}


inline bool
buffer_can_write(buffer *b) {
    return b->limit - b->write > 0;
}

inline uint8_t *
buffer_write_ptr(buffer *b, size_t *nbyte) {
    assert(b->write <= b->limit);
    *nbyte = b->limit - b->write;
    return b->write;
}

inline bool
buffer_can_read(buffer *b) {
    return b->write - b->read > 0;
}

inline uint8_t *
buffer_read_ptr(buffer *b, size_t *nbyte) {
    assert(b->read <= b->write);
    *nbyte = b->write - b->read;
    return b->read;
}

inline void
buffer_write_adv(buffer *b, const ssize_t bytes) {
    if(bytes > -1) {
        b->write += (size_t) bytes;
        assert(b->write <= b->limit);
    }
}

inline void
buffer_read_adv(buffer *b, const ssize_t bytes) {
    if(bytes > -1) {
        b->read += (size_t) bytes;
        assert(b->read <= b->write);

        if(b->read == b->write) {
            // compactacion poco costosa
            buffer_compact(b);
        }
    }
}

inline uint8_t
buffer_read(buffer *b) {
    uint8_t ret;
    if(buffer_can_read(b)) {
        ret = *b->read;
        buffer_read_adv(b, 1);
    } else {
        ret = 0;
    }
    return ret;
}

inline void
buffer_write(buffer *b, uint8_t c) {
    if(buffer_can_write(b)) {
        *b->write = c;
        buffer_write_adv(b, 1);
    }
}

void
buffer_compact(buffer *b) {
    if(b->data == b->read) {
        // nada por hacer
    } else if(b->read == b->write) {
        b->read  = b->data;
        b->write = b->data;
    } else {
        const size_t n = b->write - b->read;
        memmove(b->data, b->read, n);
        b->read  = b->data;
        b->write = b->data + n;
    }
}
