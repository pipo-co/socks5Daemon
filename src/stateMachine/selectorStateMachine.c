/**
 * selectorStateMachine.c - pequeño motor de maquina de estados donde los eventos son los
 *         del selector.c
 */
#include <stdlib.h>
#include "selectorStateMachine.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

void
selector_state_machine_init(SSM ssm, unsigned initialState, unsigned maxState, SelectorStateDefinition *stateDefinitions) {

    ssm->started = false;
    ssm->initial = initialState;
    ssm->current = initialState;
    ssm->maxState = maxState;
    ssm->states = stateDefinitions;

    // verificamos que los estados son correlativos, y que están bien asignados.
    for(unsigned i = 0 ; i <= ssm->maxState; i++) {
        if(ssm->states[i].state != i) {        
            abort();
        }
    }

    // Al menos dos estados
    if(ssm->initial >= ssm->maxState) {
        abort();
    }
}

inline static void
handle_first(SSM ssm, SelectorEvent *event) {
    if(!ssm->started) {
        ssm->started = true;
        if(ssm->states[ssm->current].on_arrival != NULL) {
            ssm->states[ssm->current].on_arrival(event);
        }
    }
}

inline static
void jump(SSM ssm, unsigned next, SelectorEvent *event) {
    if(next > ssm->maxState) {
        abort();
    }
    if(ssm->current != next) {
        if(ssm->states[ssm->current].on_departure != NULL) {
            ssm->states[ssm->current].on_departure(event);
        }

        ssm->current = next;

        if(ssm->states[ssm->current].on_arrival != NULL) {
            ssm->states[ssm->current].on_arrival(event);
        }
    }
}

unsigned selector_state_machine_proccess_read(SSM ssm, SelectorEvent *event) {
    handle_first(ssm, event);

    if(ssm->states[ssm->current].on_read == NULL) {
        return ssm->current;
    }

    const unsigned int ret = ssm->states[ssm->current].on_read(event);
    jump(ssm, ret, event);

    return ret;
}

unsigned selector_state_machine_proccess_write(SSM ssm, SelectorEvent *event) {
    handle_first(ssm, event);

    if(ssm->states[ssm->current].on_write == NULL) {
        return ssm->current;
    }

    const unsigned int ret = ssm->states[ssm->current].on_write(event);
    jump(ssm, ret, event);

    return ret;
}

void
selector_state_machine_close(SSM ssm, SelectorEvent *event) {
    if(ssm->states[ssm->current].on_departure != NULL) {
        ssm->states[ssm->current].on_departure(event);
    }
}

inline unsigned
selector_state_machine_state(SSM ssm) {
    return ssm->current;
}

