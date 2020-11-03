
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
// #include CLOSE
// #include FINISH

typedef SelectorStateDefinition (*SelectorStateDefinitionSupplier)(void);

static SelectorStateDefinition sessionStateDefinitions[FINISH];

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
    // #include FORWARDING
    // #include CLOSE
    // #include FINISH
}

void build_socks_session_state_machine(SSM ssm) {
    // TODO: sacar el -1 de maxState
    selector_state_machine_init(ssm, HELLO, FINISH - 1, sessionStateDefinitions);
}