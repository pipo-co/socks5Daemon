#include "stateMachine.h"

void state_machine_init(StateMachine * stm){}

void state_machine_proccess_post_read(StateMachine * stm, struct selector_key *key){}

void state_machine_proccess_pre_write(StateMachine * stm, struct selector_key *key){}

void state_machine_proccess_post_write(StateMachine * stm, struct selector_key *key){}

bool state_machine_is_done(StateMachine * stm){return false;}