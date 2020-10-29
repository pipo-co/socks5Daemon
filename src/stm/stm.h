#ifndef STM_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define STM_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

/**
 * stm.c - pequeño motor de maquina de estados donde los eventos son los
 *         del selector.c
 *
 * La interfaz es muy simple, y no es un ADT.
 *
 * Los estados se identifican con un número entero (típicamente proveniente de
 * un enum).
 *
 *  - El usuario instancia un `struct state_machine'
 *  - Describe la maquina de estados:
 *      - describe el estado inicial en `initial'
 *      - todos los posibles estados en `states' (el orden debe coincidir con
 *        el identificador)
 *      - describe la cantidad de estados en `states'.
 *
 * Provee todas las funciones necesitadas en un `struct fd_handler'
 * de selector.c.
 */

struct state_machine {
    /** declaración de cual es el estado inicial */
    unsigned                      initial;
    /**
     * declaracion de los estados: deben estar ordenados segun .[].state.
     */
    const struct state_definition *states;
    /** cantidad de estados */
    unsigned                      max_state;
    /** estado actual */
    const struct state_definition *current;
};

struct selector_key *key;

/**
 * definición de un estado de la máquina de estados
 */
struct state_definition {
    /**
     * identificador del estado: típicamente viene de un enum que arranca
     * desde 0 y no es esparso.
     */
    unsigned state;

    /** ejecutado al arribar al estado */
    void     (*on_arrival)    (const unsigned state, struct selector_key *key);
    /** ejecutado al salir del estado */
    void     (*on_departure)  (const unsigned state, struct selector_key *key);
    /** ejecutado cuando hay datos disponibles para ser leidos */
    unsigned (*on_read_ready) (struct selector_key *key);
    /** ejecutado cuando hay datos disponibles para ser escritos */
    unsigned (*on_write_ready)(struct selector_key *key);
    /** ejecutado cuando hay una resolución de nombres lista */
    unsigned (*on_block_ready)(struct selector_key *key);
};


/** inicializa el la máquina */
void
stm_init(struct state_machine *stm);

/** obtiene el identificador del estado actual */
unsigned
stm_state        (struct state_machine *stm);

/** indica que ocurrió el evento read. retorna nuevo id de nuevo estado. */
unsigned
stm_handler_read(struct state_machine *stm, struct selector_key *key);

/** indica que ocurrió el evento write. retorna nuevo id de nuevo estado. */
unsigned
stm_handler_write(struct state_machine *stm, struct selector_key *key);

/** indica que ocurrió el evento block. retorna nuevo id de nuevo estado. */
unsigned
stm_handler_block(struct state_machine *stm, struct selector_key *key);

/** indica que ocurrió el evento close. retorna nuevo id de nuevo estado. */
void
stm_handler_close(struct state_machine *stm, struct selector_key *key);

#endif