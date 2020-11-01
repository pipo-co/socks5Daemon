#include "request.h"

void request_on_arrival (const unsigned state, struct selector_key *key){
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    request_parser_init(&socks5_p->request_parser);
}

unsigned request_on_post_read(struct selector_key *key){
     
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;
    bool errored;

    if(!request_parser_consume(&socks5_p->input, &socks5_p->request_parser, &errored)){
        return socks5_p->stm.current;
    }
    if (errored == true){
        //loggear ( request_parser_error_message(socks5_p->request_parser.current_state);)
        return REQUEST_ERROR;
    }

    if (socks5_p->request_parser.version != SOCKS_VERSION){
        //loggear ("Request: Invalid version!")
        return REQUEST_ERROR;
    }
    
    if (socks5_p->request_parser.cmd != REQUEST_PARSER_COMMAND_CONNECT){
        //loggear ("Request: Unsupported command!")
        return REQUEST_ERROR;
    }
    
    if(socks5_p->request_parser.addressType == REQUEST_PARSER_ADD_TYPE_DOMAIN_NAME){
        // connectDoh(socks5_p)
        return GENERATE_DNS_QUERY;
    }
    else{

    if(socks5_p->request_parser.addressType == REQUEST_PARSER_ADD_TYPE_IP4){
        socks5_p->sock = new_ipv4_socket(socks5_p->request_parser.address, socks5_p->request_parser.port);    
    }
    else if(socks5_p->request_parser.addressType == REQUEST_PARSER_ADD_TYPE_IP6){
       socks5_p->sock = new_ipv6_socket(socks5_p->request_parser.address, socks5_p->request_parser.port);
    }
    if (socks5_p->sock == -1){
        if(errno == ENETUNREACH){
            socks5_p->rep = NETWORK_UNREACHABLE;
        }
        else if(errno = EHOSTUNREACH){
            socks5_p->rep = HOST_UNREACHABLE;
        }
        else if(errno = ECONNREFUSED){
            socks5_p->rep = CONNECTION_REFUSED;
        }
        else
        {
            socks5_p->rep = GENERAL_SOCKS_SERVER_FAILURE; // arbitrario, revisar
        }
        //logger stderr(errno);
        return REQUEST_ERROR;      
    }
    
        return IP_CONNECT;
}

