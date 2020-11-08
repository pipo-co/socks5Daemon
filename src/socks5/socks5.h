#ifndef SOCKS5_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define SOCKS5_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

#include "selector/selector.h"
#include "buffer/buffer.h"
#include "stateMachine/selectorStateMachine.h"
#include "socks5/socks5SessionDefinition.h"
#include "argsHandler/argsHandler.h"

void socks5_init(Socks5Args *argsParam, double maxSessionInactivityParam);

bool socks5_set_io_buffer_size(uint32_t size);

bool socks5_set_max_session_inactivity(uint8_t seconds);

void socks5_passive_accept_ipv4(SelectorEvent *event);

void socks5_passive_accept_ipv6(SelectorEvent *event);

void socks5_register_server(FdSelector s, SessionHandlerP session);

void socks5_cleanup_session(SelectorEvent *event);

void socks5_register_dns(FdSelector s, SessionHandlerP session);

Socks5Args *socks5_get_args(void);

#endif