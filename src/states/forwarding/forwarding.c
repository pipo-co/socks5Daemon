#include "forwarding.h"

#include "argsHandler/argsHandler.h"
#include "socks5/socks5.h"
#include "states/stateUtilities/request/requestUtilities.h"

static unsigned forwarding_on_read(SelectorEvent *event);
static unsigned forwarding_on_write(SelectorEvent *event);
static void forwarding_on_arrival(SelectorEvent *event);
static void forwarding_calculate_and_set_new_fd_interest(SelectorEvent *event);

static void forwarding_on_arrival(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    forwarding_calculate_and_set_new_fd_interest(event);

    Socks5Args *args = socks5_get_args();

    session->socksHeader.spoofingHeader.spoofingEnabled = args->disectors_enabled;

    if(session->socksHeader.spoofingHeader.spoofingEnabled) {

        session->socksHeader.spoofingHeader.bytesRead = 0;
        spoofing_parser_init(&session->socksHeader.spoofingHeader.parser);
    }
}

static unsigned forwarding_on_read(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    if(session->clientConnection.state != OPEN || session->serverConnection.state != OPEN) {
        return FLUSH_CLOSER;
    }

    forwarding_calculate_and_set_new_fd_interest(event);

    if(session->socksHeader.spoofingHeader.spoofingEnabled && !spoofing_parser_is_done(&session->socksHeader.spoofingHeader.parser)) {

        SpoofingParserSenderType senderType;
        Buffer *spoofingBuffer;
        size_t nbytes; // Not used

        if(event->fd == session->clientConnection.fd) {
            senderType = SPOOF_CLIENT;
            spoofingBuffer = &session->input;
        }

        else {
            senderType = SPOOF_SERVER;
            spoofingBuffer = &session->output;
        }

        size_t bytesRead = session->socksHeader.spoofingHeader.bytesRead;

        uint8_t *spoofingDataEnd = buffer_write_ptr(spoofingBuffer, &nbytes);

        uint8_t *spoofingDataStart = spoofingDataEnd - bytesRead;

        spoofing_parser_spoof(&session->socksHeader.spoofingHeader.parser, spoofingDataStart, bytesRead, senderType);

        // Done Spoofing
        if(spoofing_parser_is_done(&session->socksHeader.spoofingHeader.parser) && session->socksHeader.spoofingHeader.parser.success) {

            log_credential_spoofing(session);
        }
    }

    return session->sessionStateMachine.current;   
}

static unsigned forwarding_on_write(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    forwarding_calculate_and_set_new_fd_interest(event);

    return session->sessionStateMachine.current;
}

/* calcula el interes que le corresponde al fd del cliente y del servidor en base 
 * al estado de los buffer de input y output correspondientes de cada uno (los del servidor
 * son los mismos que los del cliente pero invertidos). Una vez calculados los setea */
static void forwarding_calculate_and_set_new_fd_interest(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    unsigned clientInterest = OP_NOOP;
    unsigned serverInterest = OP_NOOP;

    if(buffer_can_write(&session->input)) {
        clientInterest |= OP_READ;
    }

    if(buffer_can_read(&session->input)) {
        serverInterest |= OP_WRITE;
    }

    if(buffer_can_write(&session->output)) {
        serverInterest |= OP_READ;
    }

    if(buffer_can_read(&session->output)) {
        clientInterest |= OP_WRITE;
    }

    selector_set_interest(event->s, session->clientConnection.fd, clientInterest);
    selector_set_interest(event->s, session->serverConnection.fd, serverInterest);
}

SelectorStateDefinition forwarding_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = FORWARDING,
        .on_arrival = forwarding_on_arrival,
        .on_read = forwarding_on_read,
        .on_write = forwarding_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
