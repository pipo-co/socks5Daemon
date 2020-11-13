#ifndef ABSTRACT_SESSION_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define ABSTRACT_SESSION_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

typedef enum SessionType {
    SOCKS5_CLIENT_SESSION,
    SOCKS5_ADMINISTRATION_SESSION,
} SessionType;

typedef struct AbstractSession {
    SessionType sessionType;
} AbstractSession;

#endif
