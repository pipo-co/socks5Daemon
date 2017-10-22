#ifndef PARSER_UTILS_H_c2f29bb6482d34fc6f94a09046bbd65a5f668acf
#define PARSER_UTILS_H_c2f29bb6482d34fc6f94a09046bbd65a5f668acf

/*
 * parser_utils.c -- factory de ciertos parsers típicos
 *
 * Provee parsers reusables, como por ejemplo para verificar que
 * un string es igual a otro de forma case insensitive.
 */
#include "parser.h"

enum string_cmp_event_types {
    STRING_CMP_MAYEQ,
    /** hay posibilidades de que el string sea igual */
    STRING_CMP_EQ,
    /** NO hay posibilidades de que el string sea igual */
    STRING_CMP_NEQ,
};

const char *
parser_utils_strcmpi_event(const enum string_cmp_event_types type);


/*
 * Crea un parser que verifica que los caracteres recibidos forment el texto
 * descripto por `s'.
 *
 * Si se recibe el evento `STRING_CMP_NEQ' el texto entrado no matchea.
 */
struct parser_definition
parser_utils_strcmpi(const char *s);

/**
 * libera recursos asociado a una llamada de `parser_utils_strcmpi'
 */
void
parser_utils_strcmpi_destroy(const struct parser_definition *p);

#endif
