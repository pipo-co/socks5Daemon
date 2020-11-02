#include "request.h"
#include <errno.h>

void request_on_arrival (const unsigned state, struct selector_key *key){
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    request_parser_init(&socks5_p->socksHeader.requestHeader.parser);
    socks5_p->socksHeader.requestHeader.bytes = 0;
    socks5_p->socksHeader.requestHeader.rep = SUCCESFUL;
}

unsigned request_on_post_read(struct selector_key *key){
     
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;
    bool errored;

    if(!request_parser_consume(&socks5_p->input, &socks5_p->socksHeader.requestHeader.parser, &errored)){
        return socks5_p->stm.current;
    }
    if (errored == true){
        //loggear ( request_parser_error_message(socks5_p->request_parser.current_state);)
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_ERROR;
    }

    if (socks5_p->socksHeader.requestHeader.parser.version != SOCKS_VERSION){
        //loggear ("Request: Invalid version!")
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_ERROR;
    }
    
    if (socks5_p->socksHeader.requestHeader.parser.cmd != REQUEST_PARSER_COMMAND_CONNECT){
        //loggear ("Request: Unsupported command!")
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_ERROR;
    }
    
    if(socks5_p->socksHeader.requestHeader.parser.addressType == REQUEST_PARSER_ADD_TYPE_DOMAIN_NAME){
        // connectDoh(socks5_p)
        //registrar al selector el fd del dns
        selector_set_interest_key(key, OP_NOOP);
        return GENERATE_DNS_QUERY;
    }
    else{

        if(socks5_p->socksHeader.requestHeader.parser.addressType == REQUEST_PARSER_ADD_TYPE_IP4){
            // socks5_p->serverConnection.fd = new_ipv4_socket(socks5_p->socksHeader.requestHeader.parser.address, socks5_p->socksHeader.requestHeader.parser.port);    
        }
        else if(socks5_p->socksHeader.requestHeader.parser.addressType == REQUEST_PARSER_ADD_TYPE_IP6){
        //    socks5_p->serverConnection.fd = new_ipv6_socket(socks5_p->socksHeader.requestHeader.parser.address, socks5_p->socksHeader.requestHeader.parser.port);
        }
        if (socks5_p->serverConnection.fd  == -1) {
            if(errno == ENETUNREACH) {
                socks5_p->socksHeader.requestHeader.rep = NETWORK_UNREACHABLE;
            }
            else if(errno = EHOSTUNREACH) {
                socks5_p->socksHeader.requestHeader.rep = HOST_UNREACHABLE;
            }
            else if(errno = ECONNREFUSED) {
                socks5_p->socksHeader.requestHeader.rep = CONNECTION_REFUSED;
            }
            else {
                socks5_p->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE; // arbitrario, revisar
            }
            //logger stderr(errno);
            selector_set_interest_key(key, OP_WRITE);
            return REQUEST_ERROR;      
        }
        socks5_register_server(key->s,socks5_p);
        selector_set_interest_key(key, OP_NOOP);
        return IP_CONNECT;
    }
}

