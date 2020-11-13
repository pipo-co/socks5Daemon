#ifndef ADMINISTRATION_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define ADMINISTRATION_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "parsers/adminRequestParser/adminRequestParser.h"
#include "parsers/adminRequestParser/adminResponseBuilder.h"
#include "argsHandler/argsHandler.h"
#include "selector/selector.h"
#include "netutils/netutils.h"
#include "socks5/socks5.h"
#include "socks5/abstractSession.h"



/**
 *  administration.c -- clase encargada de manejar conexiones que usen el protocolo Pipo
 * 
 *  Un cliente se conecta con el servidor en el puerto 1080 y establece una conexión
 * 
 *  En primer lugar deberá autenticarse, solo un usuario valido podra usar esta funcionalidad.
 *  
 *  Una vez autenticado, el usuario podra pedirle al administrador cualquiera de los comandos 
 *  ofrecidos por el protocolo
 * 
 *  Se reciben los datos enviados por el cliente, se parsean, y se devuelven los datos 
 *  correspondientes al resultado
 * 
 **/


/* Estados en los que puede encontrarse una conexion */
typedef enum AdminStateEnum {
    ADMIN_AUTH_ARRIVAL,
    ADMIN_AUTHENTICATING,
    ADMIN_AUTH_ACK,
    ADMIN_METHOD_ARRIVAL,
    ADMIN_METHOD,
    ADMIN_METHOD_RESPONSE,
    ADMIN_FINISH,
    ADMIN_AUTH_ERROR,
    ADMIN_METHOD_ERROR
 } AdminStateEnum;

/* posibles codigos de estado */
typedef enum AuthCodesStateEnum {
    SUCCESS,
    AUTH_FAILED,
    INVALID_VERSION
} AuthCodesStateEnum;

/* estructura contenedora del parser de autenticacion y su estado */
typedef struct AdminAuthHeader {
    AuthRequestParser authParser;
    /* bytes de la respuesta que ya han sido escritos */
    size_t bytes;
    AuthCodesStateEnum status;

} AdminAuthHeader;

/* estructura contenedora del parser del request del usuario y 
* el encargado de enviar la respuesta correspondiente en base al comando */

typedef struct AdminRequestHeader{
    AdminRequestParser requestParser;
    AdminResponseBuilderContainer responseBuilder;

} AdminRequestHeader;

/* el usuario o se esta autenticando o esta enviando un pedido pero nunca
* ambas cosas a la vez */
typedef union AdminHeaders{
    AdminAuthHeader authHeader;    
    AdminRequestHeader requestHeader;
} AdminHeaders;

/* Caracteriza una sesion de un cliente con el administrador con sus buffer
de entrada y salida, el encabezado correspondiente al estado en que se encuentra
la conexion y el usuario que esta conectado */
typedef struct AdministrationSession {
    SessionType sessionType;

    Buffer input;
    Buffer output;
    
    AdminHeaders adminHeader;

    AdminStateEnum currentState;

    UserInfoP user;
    
} AdministrationSession;

typedef AdministrationSession * AdministrationSessionP;

/* encargado de inicializar el handler que se usara para las conexiones con el 
administrador */
void administration_init(void);

/* encargado de aceptar conexiones para ipv4, generarles su sesion y cargarlos
en el selector */
void admin_passive_accept_ipv4(SelectorEvent *event);


/* encargado de aceptar conexiones para ipv6, generarles su sesion y cargarlos
en el selector */
void admin_passive_accept_ipv6(SelectorEvent *event);

void admin_close_session(SelectorEvent *event);

#endif
