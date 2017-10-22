#ifndef PARSER_H_00180a6350a1fbe79f133adf0a96eb6685c242b6
#define PARSER_H_00180a6350a1fbe79f133adf0a96eb6685c242b6

/**
 * parser.c -- pequeño motor para parsers/lexers.
 *
 * El usuario describe estados y transiciones.
 * Las transiciones contienen una condición, un estado destino y acciones.
 *
 * El usuario provee al parser con bytes y éste retona eventos que pueden
 * servir para delimitar tokens o accionar directamente.
 */
#include <stdint.h>
#include <stddef.h>

/**
 * Evento que retorna el parser.
 * Cada tipo de evento tendrá sus reglas en relación a data.
 */
struct parser_event {
    /** tipo de evento */
    unsigned type;
    /** caracteres asociados al evento */
    uint8_t  data[3];
    /** cantidad de datos en el buffer `data' */
    uint8_t  n;

    /** lista de eventos: si es diferente de null ocurrieron varios eventos */
    struct parser_event *next;
};

/** describe una transición entre estados  */
struct parser_state_transition {
    /* condición: un caracter o una clase de caracter. Por ej: '\r' */
    int       when;
    /** descriptor del estado destino cuando se cumple la condición */
    unsigned  dest;
    /** acción 1 que se ejecuta cuando la condición es verdadera. requerida. */
    void    (*act1)(struct parser_event *ret, const uint8_t c);
    /** otra acción opcional */
    void    (*act2)(struct parser_event *ret, const uint8_t c);
};

/** predicado para utilizar en `when' que retorna siempre true */
static const unsigned ANY = 1 << 9;

/** declaración completa de una máquina de estados */
struct parser_definition {
    /** cantidad de estados */
    const unsigned                         states_count;
    /** por cada estado, sus transiciones */
    const struct parser_state_transition **states;
    /** cantidad de estados por transición */
    const size_t                          *states_n;

    /** estado inicial */
    const unsigned                         start_state;
};

/**
 * inicializa el parser.
 *
 * `classes`: caracterización de cada caracter (256 elementos)
 */
struct parser *
parser_init    (const unsigned *classes,
                const struct parser_definition *def);

/** destruye el parser */
void
parser_destroy  (struct parser *p);

/** permite resetear el parser al estado inicial */
void
parser_reset    (struct parser *p);

/**
 * el usuario alimenta el parser con un caracter, y el parser retorna un evento
 * de parsing. Los eventos son reusado entre llamadas por lo que si se desea
 * capturar los datos se debe clonar.
 */
const struct parser_event *
parser_feed     (struct parser *p, const uint8_t c);

/**
 * En caso de la aplicacion no necesite clases caracteres, se
 * provee dicho arreglo para ser usando en `parser_init'
 */
const unsigned *
parser_no_classes(void);


#endif
