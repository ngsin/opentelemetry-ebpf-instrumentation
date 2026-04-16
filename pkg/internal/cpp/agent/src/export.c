/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - Unix domain socket export channel
 *
 * Sends serialized obi_span_event structs to the Go-side SpanReader.
 * Uses non-blocking I/O to avoid stalling the target process.
 */

#define _GNU_SOURCE
#include "export.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

/* Export socket file descriptor (-1 = not connected) */
static int g_export_fd = -1;

/* Maximum retries for connection */
#define EXPORT_MAX_RETRIES 3

__attribute__((visibility("hidden")))
int obi_export_init(const char *socket_path) {
    struct sockaddr_un addr;
    int fd;

    if (!socket_path || socket_path[0] == '\0') {
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    /* Try to connect with retries */
    int connected = 0;
    for (int i = 0; i < EXPORT_MAX_RETRIES; i++) {
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            connected = 1;
            break;
        }
        /* Brief delay between retries */
        usleep(100 * 1000); /* 100ms */
    }

    if (!connected) {
        close(fd);
        return -1;
    }

    /* Set non-blocking to avoid stalling the target process */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    g_export_fd = fd;
    return 0;
}

__attribute__((visibility("hidden")))
int obi_export_send(const struct obi_span_event *event,
                    const char *method, uint32_t method_len,
                    const char *url, uint32_t url_len) {
    if (g_export_fd < 0 || !event) {
        return -1;
    }

    /*
     * Wire format: fixed header (OBI_SPAN_EVENT_FIXED_SIZE bytes)
     *            + method (method_len bytes)
     *            + url (url_len bytes)
     *
     * Use writev for scatter-gather I/O to avoid copying.
     */
    struct iovec iov[3];
    int iovcnt = 0;

    /* Fixed header */
    iov[iovcnt].iov_base = (void *)event;
    iov[iovcnt].iov_len = OBI_SPAN_EVENT_FIXED_SIZE;
    iovcnt++;

    /* Variable: method */
    if (method_len > 0 && method) {
        iov[iovcnt].iov_base = (void *)method;
        iov[iovcnt].iov_len = method_len;
        iovcnt++;
    }

    /* Variable: url */
    if (url_len > 0 && url) {
        iov[iovcnt].iov_base = (void *)url;
        iov[iovcnt].iov_len = url_len;
        iovcnt++;
    }

    ssize_t n = writev(g_export_fd, iov, iovcnt);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Socket buffer full - drop this span silently */
            return -1;
        }
        /* Connection broken - close and mark as disconnected */
        close(g_export_fd);
        g_export_fd = -1;
        return -1;
    }

    return 0;
}

__attribute__((visibility("hidden")))
void obi_export_shutdown(void) {
    if (g_export_fd >= 0) {
        close(g_export_fd);
        g_export_fd = -1;
    }
}
