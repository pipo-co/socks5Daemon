#ifndef STM_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define STM_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

#include "selector/selector.h"
#include <stdbool.h>

/**
 * stm.c - pequeño motor de maquina de estados donde los eventos son los
 *         del selector.c
 *
 * La interfaz es muy simple, y no es un ADT.
 *
 * Los estados se identifican con un número entero (típicamente proveniente de
 * un enum).
 *
 *  - El usuario instancia `SelectorStateMachine'
 *  - Describe la maquina de estados:
 *      - describe el estado inicial en `initial'
 *      - todos los posibles estados en `states' (el orden debe coincidir con
 *        el identificador)
 *      - describe la cantidad de estados en `states'.
 *
 * Provee todas las funciones necesitadas en un `FdHandler'
 * de selector.c.
 */

typedef unsigned (*StateFunction)(SelectorEvent*);

typedef struct SelectorStateDefinition {
    /**
     * identificador del estado: típicamente viene de un enum que puede arrancar en 0 y no es esparso.
     */
    unsigned state;

    /** ejecutado al arribar al estado */
    void (*on_arrival)(SelectorEvent*);

    /** ejecutado al salir del estado */
    void (*on_departure)(SelectorEvent*);

    /** ejecutado cuando fueron leidos nuevos datos */
    StateFunction on_post_read;

    /** ejecutado antes de escribir datos nuevos */
    StateFunction on_pre_write;

    /** ejecutado cuando fueron escritos datos nuevos */
    StateFunction on_post_write;

    /** ejecutado cuando se vuelve de una operación bloqueante resuelto con un thread (para expansion futura) */
    StateFunction on_block_ready;

} SelectorStateDefinition;

typedef struct SelectorStateMachine {
    /** declaración de cual es el estado inicial */
    unsigned                      initial;

    /** estado actual */
    unsigned                      current;

    /**
     * declaración de los estados y sus transiciones, ordenados por numero de estado. Es constante.
     */
    SelectorStateDefinition *states;

    /** estado maximo (para calcular cantidad de estados) */
    unsigned                      maxState;

    /** si la maquina de estados ya empezó a correr */
    bool started;

} SelectorStateMachine;

typedef SelectorStateMachine * SSM;

void selector_state_machine_init(SSM ssm, unsigned initialState, unsigned maxState, SelectorStateDefinition *stateDefinitions);

unsigned selector_state_machine_proccess_post_read(SSM ssm, SelectorEvent *event);

unsigned selector_state_machine_proccess_pre_write(SSM ssm, SelectorEvent *event);

unsigned selector_state_machine_proccess_post_write(SSM ssm, SelectorEvent *event);

void selector_state_machine_close(SSM ssm, SelectorEvent *event);

unsigned selector_state_machine_state(SSM ssm);

#endif