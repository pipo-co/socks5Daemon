#ifndef SELECTOR_H_W50GNLODsARolpHbsDsrvYvMsbT
#define SELECTOR_H_W50GNLODsARolpHbsDsrvYvMsbT

#include <sys/time.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * selector.c - un muliplexor de entrada salida
 *
 * Un selector permite manejar en un único hilo de ejecución la entrada salida
 * de file descriptors de forma no bloqueante.
 *
 * Esconde la implementación final (select(2) / poll(2) / epoll(2) / ..)
 *
 * El usuario registra para un file descriptor especificando:
 *  1. un handler: provee funciones callback que manejarán los eventos de
 *     entrada/salida
 *  2. un interés: que especifica si interesa leer o escribir.
 *
 * Es importante que los handlers no ejecute tareas bloqueantes ya que demorará
 * el procesamiento del resto de los descriptores.
 *
 * Si el handler requiere bloquearse por alguna razón (por ejemplo realizar
 * una resolución de DNS utilizando getaddrinfo(3)), tiene la posiblidad de
 * descargar el trabajo en un hilo notificará al selector que el resultado del
 * trabajo está disponible y se le presentará a los handlers durante
 * la iteración normal. Los handlers no se tienen que preocupar por la
 * concurrencia.
 *
 * Dicha señalización se realiza mediante señales, y es por eso que al
 * iniciar la librería `selector_init' se debe configurar una señal a utilizar.
 *
 * Todos métodos retornan su estado (éxito / error) de forma uniforme.
 * Puede utilizar `selector_error' para obtener una representación human
 * del estado. Si el valor es `SELECTOR_IO' puede obtener información adicional
 * en errno(3).
 *
 * El flujo de utilización de la librería es:
 *  - iniciar la libreria `selector_init'
 *  - crear un selector: `selector_new'
 *  - registrar un file descriptor: `selector_register_fd'
 *  - esperar algún evento: `selector_iteratate'
 *  - destruir los recursos de la librería `selector_close'
 */
typedef struct FdSelectorCDT * FdSelector;

/** valores de retorno. */
typedef enum SelectorStatus {
    /** llamada exitosa */
    SELECTOR_SUCCESS  = 0,
    /** no pudimos alocar memoria */
    SELECTOR_ENOMEM   = 1,
    /** llegamos al límite de descriptores que la plataforma puede manejar */
    SELECTOR_MAXFD    = 2,
    /** argumento ilegal */
    SELECTOR_IARGS    = 3,
    /** descriptor ya está en uso */
    SELECTOR_FDINUSE  = 4,
    /** I/O error check errno */
    SELECTOR_IO       = 5,
    /** error restableciendo signal handler */
    SELECTOR_CLOSEERR = 6,
} SelectorStatus;

/** retorna una descripción humana del fallo */
const char *
selector_error(const SelectorStatus status);

/** opciones de inicialización del selector */
struct selector_init {
    /** señal a utilizar para notificaciones internas */
    const int signal;

    /** tiempo máximo de bloqueo durante `selector_iteratate' */
    struct timespec select_timeout;
};

/** inicializa la librería */
SelectorStatus
selector_init(const struct selector_init *c);

/** deshace la incialización de la librería */
SelectorStatus
selector_close(void);

/* instancia un nuevo selector. returna NULL si no puede instanciar  */
FdSelector
selector_new(const size_t initial_elements);

/** destruye un selector creado por _new. Tolera NULLs */
void
selector_destroy(FdSelector s);

/**
 * Intereses sobre un file descriptor (quiero leer, quiero escribir, …)
 *
 * Son potencias de 2, por lo que se puede requerir una conjunción usando el OR
 * de bits.
 *
 * OP_NOOP es útil para cuando no se tiene ningún interés.
 */
typedef enum FdInterest {
    OP_NOOP    = 0,
    OP_READ    = 1 << 0,
    OP_WRITE   = 1 << 2,
} FdInterest;

/**
 * Quita un interés de una lista de intereses
 */
#define INTEREST_OFF(FLAG, MASK)  ( (FLAG) & ~(MASK) )

/**
 * Argumento de todas las funciones callback del handler
 */
typedef struct SelectorEvent {
    /** el selector que dispara el evento */
    FdSelector s;
    /** el file descriptor en cuestión */
    int         fd;
    /** dato provisto por el usuario */
    void *      data;
} SelectorEvent;

typedef void (*SelectorEventHandler)(SelectorEvent *event);

/**
 * Manejador de los diferentes eventos..
 */
typedef struct FdHandler {
  SelectorEventHandler handle_read;
  SelectorEventHandler handle_write;
  SelectorEventHandler handle_block;
  /**
   * llamado cuando se se desregistra el fd
   * Seguramente deba liberar los recusos alocados en data.
   */
  SelectorEventHandler handle_close;
} FdHandler;

/**
 * registra en el selector `s' un nuevo file descriptor `fd'.
 *
 * Se especifica un `interest' inicial, y se pasa handler que manejará
 * los diferentes eventos. `data' es un adjunto que se pasa a todos
 * los manejadores de eventos.
 *
 * No se puede registrar dos veces un mismo fd.
 *
 * @return 0 si fue exitoso el registro.
 */
SelectorStatus
selector_register(FdSelector        s,
                  const int          fd,
                  const FdHandler  *handler,
                  const FdInterest  interest,
                  void *data);

/**
 * desregistra un file descriptor del selector
 */
SelectorStatus
selector_unregister_fd(FdSelector   s,
                       const int     fd);

/** permite cambiar los intereses para un file descriptor */
SelectorStatus
selector_set_interest(FdSelector s, int fd, FdInterest i);

/** permite cambiar los intereses para un file descriptor */
SelectorStatus
selector_set_interest_event(SelectorEvent *event, FdInterest i);

SelectorStatus
selector_add_interest(FdSelector s, int fd, FdInterest i);

SelectorStatus
selector_add_interest_event(struct SelectorEvent *event, FdInterest i);

SelectorStatus
selector_remove_interest(FdSelector s, int fd, FdInterest i);

SelectorStatus
selector_remove_interest_event(struct SelectorEvent *event, FdInterest i);

/**
 * se bloquea hasta que hay eventos disponible y los despacha.
 * Retorna luego de cada iteración, o al llegar al timeout.
 */
SelectorStatus
selector_select(FdSelector s);


/** notifica que un trabajo bloqueante terminó */
SelectorStatus
selector_notify_block(FdSelector s,
                 const int   fd);

void 
selector_update_timeout(FdSelector s, time_t timeout);

void
selector_fd_cleanup(FdSelector s, void (*cleanup_function)(SelectorEvent *, void*), void *arg);

time_t
selector_get_timeout(FdSelector s);

#endif
