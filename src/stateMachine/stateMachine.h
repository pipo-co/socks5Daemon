#ifndef STM_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define STM_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

#include "../selector/selector.h"

typedef struct StateMachine
{
   unsigned current;

}StateMachine;

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
    unsigned (*on_post_read) (struct selector_key *key);
    
    unsigned (*on_pre_write) (struct selector_key *key);
    /** ejecutado cuando hay datos disponibles para ser escritos */
    unsigned (*on_post_write) (struct selector_key *key);
    
};

void state_machine_init(StateMachine * stm);

void state_machine_proccess_post_read(StateMachine * stm, struct selector_key *key);

void state_machine_proccess_pre_write(StateMachine * stm, struct selector_key *key);

void state_machine_proccess_post_write(StateMachine * stm, struct selector_key *key);

bool state_machine_is_done(StateMachine * stm);

#endif