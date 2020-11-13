/**
 * selector.c - un muliplexor de entrada salida
 */

#include <stdio.h>  // perror
#include <stdlib.h> // malloc
#include <string.h> // memset
#include <assert.h> // :)
#include <errno.h>  // :)
#include <pthread.h>

#include <stdint.h> // SIZE_MAX
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>


#include "selector.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

#define ERROR_DEFAULT_MSG "something failed"

/** retorna una descripción humana del fallo */
const char *
selector_error(const SelectorStatus status) {
    const char *msg;
    switch(status) {
        case SELECTOR_SUCCESS:
            msg = "Success";
            break;
        case SELECTOR_ENOMEM:
            msg = "Not enough memory";
            break;
        case SELECTOR_MAXFD:
            msg = "Can't handle any more file descriptors";
            break;
        case SELECTOR_IARGS:
            msg = "Illegal argument";
            break;
        case SELECTOR_IO:
            msg = "I/O error";
            break;
            case SELECTOR_CLOSEERR:
            msg = "Cannot restablish previous signal handler";
            break;
        default:
            msg = ERROR_DEFAULT_MSG;
    }
    return msg;
}


static void
wake_handler(const int signal) {
    // nada que hacer. está solo para interrumpir el select
}

// señal a usar para las notificaciones de resolución
struct selector_init conf;
static sigset_t emptyset, blockset;
static struct sigaction oldact;

SelectorStatus
selector_init(const struct selector_init  *c) {
    memcpy(&conf, c, sizeof(conf));

    // inicializamos el sistema de comunicación entre threads y el selector
    // principal. La técnica se encuentra descripta en
    // "The new pselect() system call" <https://lwn.net/Articles/176911/>
    //  March 24, 2006
    SelectorStatus   ret = SELECTOR_SUCCESS;
    struct sigaction act;
    act.sa_handler = wake_handler;

    // 0. calculamos mascara para evitar que se interrumpa antes de llegar al
    //    select
    sigemptyset(&blockset);
    sigaddset  (&blockset, conf.signal);
    if(-1 == sigprocmask(SIG_BLOCK, &blockset, NULL)) {
        ret = SELECTOR_IO;
        goto selector_init_finally;
    }

    // 1. Registramos una función que atenderá la señal de interrupción
    //    del selector.
    //    Esta interrupción es útil en entornos multi-hilos.

    if (sigaction(conf.signal, &act, &oldact)) {
        ret = SELECTOR_IO;
        goto selector_init_finally;
    }
    sigemptyset(&emptyset);

selector_init_finally:
    return ret;
}

SelectorStatus
selector_close(void) {
    // Nada para liberar.
    
    if(sigaction(conf.signal, &oldact, NULL))
        return SELECTOR_CLOSEERR;

    return SELECTOR_SUCCESS;
}

// estructuras internas
struct Item {
   int                 fd;
   FdInterest         interest;
   const FdHandler   *handler;
   void *              data;
};

/* tarea bloqueante */
struct BlockingJob {
    /** selector dueño de la resolucion */
    FdSelector  s;
    /** file descriptor dueño de la resolucion */
    int fd;

    /** datos del trabajo provisto por el usuario */
    void *data;

    /** el siguiente en la lista */
    struct BlockingJob *next;
};

/** marca para usar en item->fd para saber que no está en uso */
static const int FD_UNUSED = -1;

/** verifica si el item está usado */
#define ITEM_USED(i) ( ( FD_UNUSED != (i)->fd) )

typedef struct FdSelectorCDT {
    // almacenamos en una jump table donde la entrada es el file descriptor.
    // Asumimos que el espacio de file descriptors no va a ser esparso; pero
    // esto podría mejorarse utilizando otra estructura de datos
    struct Item    *fds;
    size_t          fd_size;  // cantidad de elementos posibles de fds

    /** fd maximo para usar en select() */
    int max_fd;  // max(.fds[].fd)

    /** descriptores prototipicos ser usados en select */
    fd_set master_r, master_w;
    /** para ser usado en el select() (recordar que select cambia el valor) */
    fd_set  slave_r,  slave_w;

    /** timeout prototipico para usar en select() */
    struct timespec master_t;
    /** tambien select() puede cambiar el valor */
    struct timespec slave_t;

    // notificaciónes entre blocking jobs y el selector
    volatile pthread_t      selector_thread;
    /** protege el acceso a resolutions jobs */
    pthread_mutex_t         resolution_mutex;
    /**
     * lista de trabajos blockeantes que finalizaron y que pueden ser
     * notificados.
     */
    struct BlockingJob    *resolution_jobs;
} FdSelectorCDT;

/** cantidad máxima de file descriptors que la plataforma puede manejar */
#define ITEMS_MAX_SIZE      FD_SETSIZE

// en esta implementación el máximo está dado por el límite natural de select(2).

/**
 * determina el tamaño a crecer, generando algo de slack para no tener
 * que realocar constantemente.
 */
static
size_t next_capacity(const size_t n) {
    unsigned bits = 0;
    size_t tmp = n;
    while(tmp != 0) {
        tmp >>= 1;
        bits++;
    }
    tmp = 1UL << bits;

    assert(tmp >= n);
    if(tmp > ITEMS_MAX_SIZE) {
        tmp = ITEMS_MAX_SIZE;
    }

    return tmp + 1;
}

static inline void
item_init(struct Item *item) {
    item->fd = FD_UNUSED;
}

/**
 * inicializa los nuevos items. `last' es el indice anterior.
 * asume que ya está blanqueada la memoria.
 */
static void
items_init(FdSelector s, const size_t last) {
    assert(last <= s->fd_size);
    for(size_t i = last; i < s->fd_size; i++) {
        item_init(s->fds + i);
    }
}

/**
 * calcula el fd maximo para ser utilizado en select()
 */
static int
items_max_fd(FdSelector s) {
    int max = 0;
    for(int i = 0; i <= s->max_fd; i++) {
        struct Item *item = s->fds + i;
        if(ITEM_USED(item)) {
            if(item->fd > max) {
                max = item->fd;
            }
        }
    }
    return max;
}

static void
items_update_fdset_for_fd(FdSelector s, const struct Item * item) {
    FD_CLR(item->fd, &s->master_r);
    FD_CLR(item->fd, &s->master_w);

    if(ITEM_USED(item)) {
        if(item->interest & OP_READ) {
            FD_SET(item->fd, &(s->master_r));
        }

        if(item->interest & OP_WRITE) {
            FD_SET(item->fd, &(s->master_w));
        }
    }
}

/**
 * garantizar cierta cantidad de elemenos en `fds'.
 * Se asegura de que `n' sea un número que la plataforma donde corremos lo
 * soporta
 */
static SelectorStatus
ensure_capacity(FdSelector s, const size_t n) {
    SelectorStatus ret = SELECTOR_SUCCESS;

    const size_t element_size = sizeof(*s->fds);
    if(n < s->fd_size) {
        // nada para hacer, entra...
        ret = SELECTOR_SUCCESS;
    } else if(n > ITEMS_MAX_SIZE) {
        // me estás pidiendo más de lo que se puede.
        ret = SELECTOR_MAXFD;
    } else if(NULL == s->fds) {
        // primera vez.. alocamos
        const size_t new_size = next_capacity(n);

        s->fds = calloc(new_size, element_size);
        if(NULL == s->fds) {
            ret = SELECTOR_ENOMEM;
        } else {
            s->fd_size = new_size;
            items_init(s, 0);
        }
    } else {
        // hay que agrandar...
        const size_t new_size = next_capacity(n);
        //raro, pvs-studio lo detecta como siempre falso
        if (new_size > SIZE_MAX/element_size) { // ver MEM07-C
            ret = SELECTOR_ENOMEM;
        } else {
            struct Item *tmp = realloc(s->fds, new_size * element_size);
            if(NULL == tmp) {
                ret = SELECTOR_ENOMEM;
            } else {
                s->fds     = tmp;
                const size_t old_size = s->fd_size;
                s->fd_size = new_size;

                items_init(s, old_size);
            }
        }
    }

    return ret;
}

FdSelector
selector_new(const size_t initial_elements) {
    size_t size = sizeof(FdSelectorCDT);
    FdSelector ret = malloc(size);
    if(ret != NULL) {
        memset(ret, 0x00, size);
        ret->master_t.tv_sec  = conf.select_timeout.tv_sec;
        ret->master_t.tv_nsec = conf.select_timeout.tv_nsec;
        assert(ret->max_fd == 0);
        ret->resolution_jobs  = 0;
        pthread_mutex_init(&ret->resolution_mutex, 0);
        if(ensure_capacity(ret, initial_elements) != SELECTOR_SUCCESS) {
            selector_destroy(ret);
            ret = NULL;
        }
    }
    return ret;
}

void
selector_destroy(FdSelector s) {
    // lean ya que se llama desde los casos fallidos de _new.
    if(s != NULL) {
        if(s->fds != NULL) {
            for(size_t i = 0; i < s->fd_size ; i++) {
                if(ITEM_USED(s->fds + i)) {
                    selector_unregister_fd(s, i);
                }
            }
            pthread_mutex_destroy(&s->resolution_mutex);
            for(struct BlockingJob *j = s->resolution_jobs; j != NULL;
                j = j->next) {
                free(j);
            }
            free(s->fds);
            s->fds     = NULL;
            s->fd_size = 0;
        }
        free(s);
    }
}

#define INVALID_FD(fd)  ((fd) < 0 || (fd) >= ITEMS_MAX_SIZE)

SelectorStatus
selector_register(FdSelector        s,
                     const int          fd,
                     const FdHandler  *handler,
                     const FdInterest  interest,
                     void *data) {
    SelectorStatus ret = SELECTOR_SUCCESS;
    // 0. validación de argumentos
    if(s == NULL || INVALID_FD(fd) || handler == NULL) {
        ret = SELECTOR_IARGS;
        goto selector_register_finally;
    }
    // 1. tenemos espacio?
    size_t ufd = (size_t)fd;
    if(ufd > s->fd_size) {
        ret = ensure_capacity(s, ufd);
        if(ret != SELECTOR_SUCCESS) {
            goto selector_register_finally;
        }
    }

    // 2. registración
    struct Item * item = s->fds + ufd;
    if(ITEM_USED(item)) {
        ret = SELECTOR_FDINUSE;
        goto selector_register_finally;
    } else {
        item->fd       = fd;
        item->handler  = handler;
        item->interest = interest;
        item->data     = data;

        // actualizo colaterales
        if(fd > s->max_fd) {
            s->max_fd = fd;
        }
        items_update_fdset_for_fd(s, item);
    }

selector_register_finally:
    return ret;
}

SelectorStatus
selector_unregister_fd(FdSelector       s,
                       const int         fd) {
    SelectorStatus ret = SELECTOR_SUCCESS;

    if(NULL == s || INVALID_FD(fd)) {
        ret = SELECTOR_IARGS;
        goto finally;
    }

    struct Item *item = s->fds + fd;
    if(!ITEM_USED(item)) {
        ret = SELECTOR_IARGS;
        goto finally;
    }

    if(item->handler->handle_close != NULL) {
        struct SelectorEvent key = {
            .s    = s,
            .fd   = item->fd,
            .data = item->data,
        };
        item->handler->handle_close(&key);
    }

    item->interest = OP_NOOP;
    items_update_fdset_for_fd(s, item);

    memset(item, 0x00, sizeof(*item));
    item_init(item);
    s->max_fd = items_max_fd(s);

finally:
    return ret;
}

SelectorStatus
selector_set_interest(FdSelector s, int fd, FdInterest i) {
    SelectorStatus ret = SELECTOR_SUCCESS;

    if(NULL == s || INVALID_FD(fd)) {
        ret = SELECTOR_IARGS;
        goto finally;
    }
    struct Item *item = s->fds + fd;
    if(!ITEM_USED(item)) {
        ret = SELECTOR_IARGS;
        goto finally;
    }
    item->interest = i;
    items_update_fdset_for_fd(s, item);
finally:
    return ret;
}

SelectorStatus
selector_set_interest_event(struct SelectorEvent *event, FdInterest i) {
    SelectorStatus ret;

    if(NULL == event || NULL == event->s || INVALID_FD(event->fd)) {
        ret = SELECTOR_IARGS;
    } else {
        ret = selector_set_interest(event->s, event->fd, i);
    }

    return ret;
}

SelectorStatus
selector_add_interest(FdSelector s, int fd, FdInterest i) {
    SelectorStatus ret = SELECTOR_SUCCESS;

    if(NULL == s || INVALID_FD(fd)) {
        ret = SELECTOR_IARGS;
        goto finally;
    }
    struct Item *item = s->fds + fd;
    if(!ITEM_USED(item)) {
        ret = SELECTOR_IARGS;
        goto finally;
    }
    item->interest |= i;
    items_update_fdset_for_fd(s, item);
finally:
    return ret;
}

SelectorStatus
selector_add_interest_event(struct SelectorEvent *event, FdInterest i) {
    SelectorStatus ret;

    if(NULL == event || NULL == event->s || INVALID_FD(event->fd)) {
        ret = SELECTOR_IARGS;
    } else {
        ret = selector_add_interest(event->s, event->fd, i);
    }

    return ret;
}

SelectorStatus
selector_remove_interest(FdSelector s, int fd, FdInterest i) {
    SelectorStatus ret = SELECTOR_SUCCESS;

    if(NULL == s || INVALID_FD(fd)) {
        ret = SELECTOR_IARGS;
        goto finally;
    }
    struct Item *item = s->fds + fd;
    if(!ITEM_USED(item)) {
        ret = SELECTOR_IARGS;
        goto finally;
    }
    item->interest &= ~i;
    items_update_fdset_for_fd(s, item);
finally:
    return ret;
}

SelectorStatus
selector_remove_interest_event(struct SelectorEvent *event, FdInterest i) {
    SelectorStatus ret;

    if(NULL == event || NULL == event->s || INVALID_FD(event->fd)) {
        ret = SELECTOR_IARGS;
    } else {
        ret = selector_remove_interest(event->s, event->fd, i);
    }

    return ret;
}

/**
 * se encarga de manejar los resultados del select.
 * se encuentra separado para facilitar el testing
 */
static void
handle_iteration(FdSelector s) {
    int n = s->max_fd;
    struct SelectorEvent key = {
        .s = s,
    };

    for (int i = 0; i <= n; i++) {
        struct Item *item = s->fds + i;
        if(ITEM_USED(item)) {
            key.fd   = item->fd;
            key.data = item->data;
            if(FD_ISSET(item->fd, &s->slave_r)) {
                if(OP_READ & item->interest) {
                    if(item->handler->handle_read == NULL) {
                        assert(("OP_READ arrived but no handler. bug!" == 0));
                    } else {
                        item->handler->handle_read(&key);
                    }
                }
            }
            if(FD_ISSET(i, &s->slave_w)) {
                if(OP_WRITE & item->interest) {
                    if(item->handler->handle_write == NULL) {
                        assert(("OP_WRITE arrived but no handler. bug!" == 0));
                    } else {
                        item->handler->handle_write(&key);
                    }
                }
            }
        }
    }
}

static void
handle_block_notifications(FdSelector s) {
    struct SelectorEvent key = {
        .s = s,
    };
    pthread_mutex_lock(&s->resolution_mutex);
    //Hace free y despues pregunta por el estado de j, pvs studio lo detecta como error
    for(struct BlockingJob *j = s->resolution_jobs;
        j != NULL ;
        j  = j->next) {

        struct Item *item = s->fds + j->fd;
        if(ITEM_USED(item)) {
            key.fd   = item->fd;
            key.data = item->data;
            item->handler->handle_block(&key);
        }

        free(j);
    }
    s->resolution_jobs = 0;
    pthread_mutex_unlock(&s->resolution_mutex);
}

SelectorStatus
selector_notify_block(FdSelector  s, const int fd) {
    SelectorStatus ret = SELECTOR_SUCCESS;

    // TODO(juan): usar un pool
    struct BlockingJob *job = malloc(sizeof(*job));
    if(job == NULL) {
        ret = SELECTOR_ENOMEM;
        goto finally;
    }
    job->s  = s;
    job->fd = fd;

    // encolamos en el selector los resultados
    pthread_mutex_lock(&s->resolution_mutex);
    job->next = s->resolution_jobs;
    s->resolution_jobs = job;
    pthread_mutex_unlock(&s->resolution_mutex);

    // notificamos al hilo principal
    pthread_kill(s->selector_thread, conf.signal);

finally:
    return ret;
}

SelectorStatus
selector_select(FdSelector s) {
    SelectorStatus ret = SELECTOR_SUCCESS;
    
    memcpy(&s->slave_r, &s->master_r, sizeof(s->slave_r));
    memcpy(&s->slave_w, &s->master_w, sizeof(s->slave_w));
    memcpy(&s->slave_t, &s->master_t, sizeof(s->slave_t));

    s->selector_thread = pthread_self();

    int fds = pselect(s->max_fd + 1, &s->slave_r, &s->slave_w, NULL, &s->slave_t,
                      &emptyset);
    if(-1 == fds) {
        switch(errno) {
            case EAGAIN:
            case EINTR:
                // si una señal nos interrumpio. ok!
                break;
            case EBADF:
                // ayuda a encontrar casos donde se cierran los fd pero no
                // se desregistraron
                // for(int i = 0 ; i < s->max_fd; i++) {
                //     if(FD_ISSET(i, &s->master_r)|| FD_ISSET(i, &s->master_w)) {
                //         if(-1 == fcntl(i, F_GETFD, 0)) {
                //             fprintf(stderr, "Bad descriptor detected: %d\n", i);
                //         }
                //     }
                // }
                ret = SELECTOR_IO;
                break;
            default:
                ret = SELECTOR_IO;
                goto finally;

        }
    } else {
        handle_iteration(s);
    }
    if(ret == SELECTOR_SUCCESS) {
        handle_block_notifications(s);
    }
finally:
    return ret;
}

void
selector_fd_cleanup(FdSelector s, void (*cleanup_function)(SelectorEvent *, void*), void *arg) {
    int n = s->max_fd;
    struct SelectorEvent event = {
        .s = s,
    };

    for (int i = 0; i <= n; i++) {
        struct Item *item = s->fds + i;
        if(ITEM_USED(item)) {
            event.fd   = item->fd;
            event.data = item->data;
            
            cleanup_function(&event, arg);
        }
    }
}

void 
selector_update_timeout(FdSelector s, time_t timeout) {
    s->master_t.tv_sec = timeout;
}

time_t
selector_get_timeout(FdSelector s) {
    return s->master_t.tv_sec;
}
