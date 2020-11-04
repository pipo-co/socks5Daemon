
#include "stateMachineBuilder.h"

#include "states/hello/hello.h"                                     // HELLO
#include "states/errorStates/helloError/helloError.h"               // HELLO_ERROR
#include "states/authMethodAnnouncement/authMethodAnnouncement.h"   // AUTH_METHOD_ANNOUNCEMENT
#include "states/authRequest/authRequest.h"                         // AUTH_REQUEST
#include "states/errorStates/authError/authError.h"                 // AUTH_ERROR
#include "states/authSuccessful/authSuccessful.h"                   // AUTH_SUCCESSFUL
#include "states/request/request.h"                                 // REQUEST
#include "states/errorStates/requestError/requestError.h"           // REQUEST_ERROR
#include "states/ipConnect/ipConnect.h"                             // IP_CONNECT
// #include DNS
#include "states/requestSuccessful/requestSuccessful.h"             // REQUEST_SUCCESSFUL
#include "states/forwarding/forwarding.h"                           // FORWARDING
#include "states/close/flushCloser/flushCloser.h"                   // FLUSH_CLOSER
#include "states/close/flushClosy/flushClosy.h"                     // FLUSH_CLOSY


static SelectorStateDefinition finish_state_definition_supplier(void);

typedef SelectorStateDefinition (*SelectorStateDefinitionSupplier)(void);

static SelectorStateDefinition sessionStateDefinitions[FINISH + 1];

static SelectorStateDefinition finish_state_definition_supplier(void) {
    SelectorStateDefinition ssd = {
        .state = FINISH,
        .on_arrival = NULL,
        .on_read = NULL,
        .on_write = NULL,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return ssd;
}

void socks5_session_state_machine_builder_init() {

    sessionStateDefinitions[HELLO]                      = hello_state_definition_supplier();
    sessionStateDefinitions[HELLO_ERROR]                = hello_error_state_definition_supplier();
    sessionStateDefinitions[AUTH_METHOD_ANNOUNCEMENT]   = auth_method_announcement_state_definition_supplier();
    sessionStateDefinitions[AUTH_REQUEST]               = auth_request_state_definition_supplier();
    sessionStateDefinitions[AUTH_ERROR]                 = auth_error_state_definition_supplier();
    sessionStateDefinitions[AUTH_SUCCESSFUL]            = auth_successful_state_definition_supplier();
    sessionStateDefinitions[REQUEST]                    = request_state_definition_supplier();
    sessionStateDefinitions[REQUEST_ERROR]              = request_error_state_definition_supplier();
    sessionStateDefinitions[IP_CONNECT]                 = ip_connect_state_definition_supplier();
    // sessionStateDefinitions[DNS]                     = dns_state_definition_supplier();
    sessionStateDefinitions[REQUEST_SUCCESSFUL]         = request_successful_state_definition_supplier();
    sessionStateDefinitions[FORWARDING]                 = forwarding_state_definition_supplier();
    sessionStateDefinitions[FLUSH_CLOSER]               = flush_closer_state_definition_supplier();
    sessionStateDefinitions[FLUSH_CLOSY]                = flush_closy_state_definition_supplier();
    sessionStateDefinitions[FINISH]                     = finish_state_definition_supplier();
}

void build_socks_session_state_machine(SSM ssm) {
    selector_state_machine_init(ssm, HELLO, FINISH, sessionStateDefinitions);
}