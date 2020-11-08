#ifndef BUFFER_H_VelRDAxzvnuFmwEaR0ftrkIinkT
#define BUFFER_H_VelRDAxzvnuFmwEaR0ftrkIinkT

#include <stdbool.h>
#include <unistd.h>  // size_t, ssize_t
#include <stdint.h>

/**
 * buffer.c - buffer con acceso directo (útil para I/O) que mantiene
 *            puntero de lectura y de escritura.
 *
 *
 * Para esto se mantienen dos punteros, uno de lectura
 * y otro de escritura, y se provee funciones para
 * obtener puntero base y capacidad disponibles.
 *
 * R=0
 * ↓
 * +---+---+---+---+---+---+
 * |   |   |   |   |   |   |
 * +---+---+---+---+---+---+
 * ↑                       ↑
 * W=0                     limit=6
 *
 * Invariantes:
 *    R <= W <= limit
 *
 * Se quiere escribir en el bufer cuatro bytes.
 *
 * ptr + 0 <- buffer_write_ptr(b, &wbytes), wbytes=6
 * n = read(fd, ptr, wbytes)
 * buffer_write_adv(b, n = 4)
 *
 * R=0
 * ↓
 * +---+---+---+---+---+---+
 * | H | O | L | A |   |   |
 * +---+---+---+---+---+---+
 *                 ↑       ↑
 *                W=4      limit=6
 *
 * Quiero leer 3 del Buffer
 * ptr + 0 <- buffer_read_ptr, wbytes=4
 * buffer_read_adv(b, 3);
 *
 *            R=3
 *             ↓
 * +---+---+---+---+---+---+
 * | H | O | L | A |   |   |
 * +---+---+---+---+---+---+
 *                 ↑       ↑
 *                W=4      limit=6
 *
 * Quiero escribir 2 bytes mas
 * ptr + 4 <- buffer_write_ptr(b, &wbytes=2);
 * buffer_write_adv(b, 2)
 *
 *            R=3
 *             ↓
 * +---+---+---+---+---+---+
 * | H | O | L | A |   | M |
 * +---+---+---+---+---+---+
 *                         ↑
 *                         limit=6
 *                         W=4
 * Compactación a demanda
 * R=0
 * ↓
 * +---+---+---+---+---+---+
 * | A |   | M |   |   |   |
 * +---+---+---+---+---+---+
 *             ↑           ↑
 *            W=3          limit=6
 *
 * Leo los tres bytes, como R == W, se auto compacta.
 *
 * R=0
 * ↓
 * +---+---+---+---+---+---+
 * |   |   |   |   |   |   |
 * +---+---+---+---+---+---+
 * ↑                       ↑
 * W=0                     limit=6
 */
typedef struct Buffer {
    uint8_t *data;

    /** límite superior del buffer. inmutable */
    uint8_t *limit;

    /** puntero de lectura */
    uint8_t *read;

    /** puntero de escritura */
    uint8_t *write;
} Buffer;

/**
 * inicializa el buffer sin utilizar el heap
 */
void
buffer_init(Buffer *b, const size_t n, uint8_t *data);

/**
 * Retorna un puntero donde se pueden escribir hasta `*nbytes`.
 * Se debe notificar mediante la función `buffer_write_adv'
 */
uint8_t *
buffer_write_ptr(Buffer *b, size_t *nbyte);
void
buffer_write_adv(Buffer *b, const ssize_t bytes);

uint8_t *
buffer_read_ptr(Buffer *b, size_t *nbyte);
void
buffer_read_adv(Buffer *b, const ssize_t bytes);

/**
 * obtiene un byte
 */
uint8_t
buffer_read(Buffer *b);

/** escribe un byte */
void
buffer_write(Buffer *b, uint8_t c);

/**
 * compacta el buffer
 */
void
buffer_compact(Buffer *b);

/**
 * Reinicia todos los punteros
 */
void
buffer_reset(Buffer *b);

/** retorna true si hay bytes para leer del buffer */
bool
buffer_can_read(Buffer *b);

/** retorna true si se pueden escribir bytes en el buffer */
bool
buffer_can_write(Buffer *b);


#endif
