#ifndef SOCKS5_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define SOCKS5_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

#include "selector/selector.h"
#include "buffer/buffer.h"
#include "stateMachine/selectorStateMachine.h"
#include "socks5/socks5SessionDefinition.h"
#include "argsHandler/argsHandler.h"

void socks5_init(Socks5Args *argsParam, double maxSessionInactivityParam, FdSelector selectorParam);

uint32_t socks5_get_io_buffer_size(void);

bool socks5_set_io_buffer_size(uint32_t size);

uint8_t socks5_get_max_session_inactivity(void);

bool socks5_set_max_session_inactivity(uint8_t seconds);

void socks5_passive_accept_ipv4(SelectorEvent *event);

void socks5_passive_accept_ipv6(SelectorEvent *event);

void socks5_register_server(SessionHandlerP session);

void socks5_selector_cleanup(void);

uint8_t socks5_get_selector_timeout(void);

bool socks5_update_selector_timeout(time_t timeout);

void socks5_close_user_sessions(UserInfoP user);

void socks5_register_dns(SessionHandlerP session);

Socks5Args *socks5_get_args(void);

#endif