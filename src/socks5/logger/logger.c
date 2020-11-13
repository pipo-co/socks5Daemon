#include "logger.h"

#include <stdint.h>
#include <errno.h>
#include <string.h>

#include "buffer/buffer.h"

#define LOG_BUFFER_SIZE  2048

static FdHandler logHandler;

static Buffer stdoutLogBuffer;
static Buffer stderrLogBuffer;

static FdSelector s;

static void logger_selector_write(SelectorEvent *event);


void logger_init(FdSelector selector) {

    s = selector;

    logHandler.handle_read = NULL;
    logHandler.handle_write = logger_selector_write;
    logHandler.handle_close = NULL;
    logHandler.handle_block = NULL;

    selector_register(s, STDOUT_FILENO, &logHandler, OP_NOOP, &stdoutLogBuffer);
    selector_register(s, STDERR_FILENO, &logHandler, OP_NOOP, &stderrLogBuffer);
}

#include <stdio.h>

static void logger_selector_write(SelectorEvent *event) {

    Buffer *buffer = (Buffer*)event->data;

    ssize_t writeBytes;
    size_t nbytes;
    uint8_t * readPtr = buffer_read_ptr(buffer, &nbytes);

    writeBytes = write(event->fd, readPtr, nbytes);

    // No se que hacer
    if(writeBytes < 0 && errno != EINTR) {
        selector_set_interest_event(event, OP_NOOP);
        return;
    }

    buffer_read_adv(buffer, writeBytes);

    if(!buffer_can_read(buffer)) {
        selector_set_interest_event(event, OP_NOOP);
    }
}

void logger_non_blocking_log(int fd, char *log, size_t nbytes) {

    int writeBytes;

    do {
        writeBytes = write(fd, log, nbytes);

        if(writeBytes > 0) {
            nbytes -= writeBytes;
            log += writeBytes;
        }

    } while(writeBytes > 0 && (fd >= 0 || errno == EINTR));

    if(writeBytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {

        size_t buffSpace;
        Buffer *buffer;

        if(fd == STDOUT_FILENO) {
            buffer = &stdoutLogBuffer;
        }
        else if(fd == STDERR_FILENO) {
            buffer = &stderrLogBuffer;
        }
        else {
            return;
        }

        uint8_t * writePtr = buffer_write_ptr(buffer, &buffSpace);

        if(buffSpace < nbytes) {
            return;
        }

        memcpy(writePtr, log, nbytes);

        buffer_write_adv(buffer, nbytes);

        selector_set_interest(s, fd, OP_WRITE);
    }
}
