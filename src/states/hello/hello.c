#include "states/hello/hello.h"

#include <stdint.h>
#include <stdbool.h>

#include "buffer/buffer.h"
#include "parsers/hello/helloParser.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

static bool on_auth_method(HelloParser *p, uint8_t currentMethod);
static void hello_on_arrival (SelectorEvent *event);
static unsigned hello_on_read(SelectorEvent *event);

static bool on_auth_method(HelloParser *p, uint8_t currentMethod) {

    static uint8_t methodPriorityList[] = {
        NO_ACCEPTABLE_METHODS, 
        NO_AUTHENTICATION, 
        USER_PASSWORD
    };
    
    if(p->data == NULL){
        return false;
    }

    uint8_t *previousMethod = (uint8_t *) p->data;

    size_t prev = 0;
    size_t curr = 0;

    for (size_t i = 0; i < N(methodPriorityList); i++){
        if(*previousMethod == methodPriorityList[i]){
            prev = i;
        }
        if(currentMethod == methodPriorityList[i]){
            curr = i;
        }
    }

    if(prev < curr){
        *previousMethod = currentMethod;
    }

    return true;
}


static void hello_on_arrival (SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->clientInfo.authMethod = NO_ACCEPTABLE_METHODS;
    
    hello_parser_init(&session->socksHeader.helloHeader.parser, on_auth_method, &session->clientInfo.authMethod);

    selector_set_interest(event->s, session->clientConnection.fd, OP_READ);
}

static unsigned hello_on_read(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;
    bool errored;
    HelloHeader * h = &session->socksHeader.helloHeader;

    if(!hello_parser_consume(&session->input, &h->parser, &errored)) {
        return session->sessionStateMachine.current;
    }

    if(errored == true) {
        //loggear ( hello_parser_error_message(socks5_p->hello_parser.current_state);)
        return HELLO_ERROR;
    }

    if(h->parser.version != SOCKS_VERSION) {
        //loggear ("Hello: Invalid version!")
        return HELLO_ERROR;
    }
    
    if(session->clientInfo.authMethod == NO_ACCEPTABLE_METHODS) {
        //loggear ("Hello: No acceptable methods!")
        return HELLO_ERROR;
    }
    
    return AUTH_METHOD_ANNOUNCEMENT;
}

SelectorStateDefinition hello_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = HELLO,
        .on_arrival = hello_on_arrival,
        .on_read = hello_on_read,
        .on_write = NULL,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
