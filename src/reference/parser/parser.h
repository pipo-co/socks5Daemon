#ifndef PARSER_H_00180a6350a1fbe79f133adf0a96eb6685c242b6
#define PARSER_H_00180a6350a1fbe79f133adf0a96eb6685c242b6

/**
 * parser.c -- pequeño motor para parsers/lexers.
 *
 * El usuario describe estados y transiciones.
 * Las transiciones contienen una condición, un estado destino y acciones.
 *
 * El usuario provee al parser con bytes y éste retorna eventos que pueden
 * servir para delimitar tokens o accionar directamente.
 */
#include <stdint.h>
#include <stddef.h>

#define MAX_STATES 50
#define TRANSITIONS_PER_STATE 3

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

struct parser_definition {
    /** cantidad de estados */
    unsigned                         states_count;
    unsigned                         start_state;
    /** por cada estado, sus transiciones */
    struct parser_state_transition   states[MAX_STATES][TRANSITIONS_PER_STATE];
    /** cantidad de estados por transición */
    size_t                            states_n[MAX_STATES];

    /** estado inicial */
};
/** predicado para utilizar en `when' que retorna siempre true */
#define ANY (1 << 9)

/** declaración completa de una máquina de estados */

struct parser {
    /** tipificación para cada caracter */
    const unsigned     *classes;
    /** definición de estados */
    struct parser_definition def;

    /* estado actual */
    unsigned            state;

    /* evento que se retorna */
    struct parser_event e1;
    /* evento que se retorna */
    struct parser_event e2;
};
/**
 * inicializa el parser.
 *
 * `classes`: caracterización de cada caracter (256 elementos)
 */
struct parser *
parser_init    (struct parser * p, const unsigned *classes, const struct parser_definition *def);

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
struct parser_event *
parser_feed     (struct parser *p, uint8_t c);

/**
 * En caso de la aplicación no necesite clases caracteres, se
 * provee dicho arreglo para ser usando en `parser_init'
 */
unsigned *
parser_no_classes(void);


#endif
