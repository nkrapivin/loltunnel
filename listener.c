#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <memory.h>
#include <asm-generic/socket.h>

struct studclient_t {
    struct studclient_t *prev, *next;
    struct sockaddr_in tcp_sockaddr;
    int from_tcp_sock;
    int to_hlds_sock;
};

static uint8_t large[65536 * 2];

int main(int argc, char *argv[], char *envp[]) {
    int ec = EXIT_FAILURE;
    const int one = 1;
    int tcpListener = -1, r = 0, csck = -1, usck = -1;

    struct sockaddr_in hldsUdp = { };
    hldsUdp.sin_family = AF_INET;
    hldsUdp.sin_port = htons(27015);
    hldsUdp.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t hldsUdpLen = sizeof(hldsUdp);

    struct sockaddr_in tcpAddress = { };
    tcpAddress.sin_family = AF_INET;
    tcpAddress.sin_port = htons(27220);
    tcpAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    struct sockaddr_in tmpAddress = { };
    tmpAddress.sin_family = AF_INET;
    socklen_t tmpAddressLen = sizeof(tmpAddress);

    struct studclient_t *head = NULL, *cur = NULL, *next = NULL, *prev = NULL;

    ssize_t rsize = 0;
    struct pollfd polldata[2] = { };

    tcpListener = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpListener < 0) {
        perror("socket");
        goto fail;
    }

    if (setsockopt(tcpListener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        goto fail;
    }

    if (setsockopt(tcpListener, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        goto fail;
    }

    if (bind(tcpListener, (struct sockaddr *)&tcpAddress, sizeof(tcpAddress)) < 0) {
        perror("bind");
        goto fail;
    }

    if (listen(tcpListener, SOMAXCONN) < 0) {
        perror("listen");
        goto fail;
    }

    polldata[0].fd = tcpListener;
    polldata[0].events = POLLIN;
    polldata[0].revents = 0;

    for (;;) {
        polldata[0].fd = tcpListener;
        polldata[0].events = POLLIN;
        polldata[0].revents = 0;
        r = poll(polldata, 1, 0);
        if (r < 0) {
            perror("poll");
            goto fail;
        }

        if (polldata[0].revents & POLLIN) {
            printf("new client...\n");
            tmpAddressLen = sizeof(tmpAddress);
            csck = accept(tcpListener, (struct sockaddr *)&tmpAddress, &tmpAddressLen);
            if (csck < 0) {
                perror("accept");
                goto fail;
            }

            usck = socket(AF_INET, SOCK_DGRAM, 0);
            if (usck < 0) {
                perror("socket");
                goto fail;
            }

            next = (struct studclient_t *)calloc(1, sizeof(struct studclient_t));
            next->from_tcp_sock = csck;
            next->to_hlds_sock = usck;
            memcpy(&next->tcp_sockaddr, &tmpAddress, sizeof(next->tcp_sockaddr));
            if (head == NULL) {
                head = next;
            } else {
                next->next = head;
                head->prev = next;
                head = next;
            }
            printf("client initialized...\n");
        }

        for (cur = head; cur != NULL;) {
            polldata[0].fd = cur->from_tcp_sock;
            polldata[0].events = POLLIN;
            polldata[0].revents = 0;
            polldata[1].fd = cur->to_hlds_sock;
            polldata[1].events = POLLIN;
            polldata[1].revents = 0;
            r = poll(polldata, 2, 0);
            if (r < 0) {
                perror("poll");
                goto fail;
            }

            if (r > 0) {
                if ((polldata[0].revents & (POLLERR | POLLHUP)) || (polldata[1].revents & (POLLERR | POLLHUP))) {
                    /* must get rid of client */
                    printf("client error condition\n");
                    if (cur->to_hlds_sock >= 0) {
                        shutdown(cur->to_hlds_sock, SHUT_RDWR);
                        close(cur->to_hlds_sock);
                    }

                    if (cur->from_tcp_sock >= 0) {
                        shutdown(cur->from_tcp_sock, SHUT_RDWR);
                        close(cur->from_tcp_sock);
                    }

                    prev = cur->prev;
                    next = cur->next;
                    if (prev != NULL) {
                        prev->next = next;
                    } else {
                        head = prev;
                    }

                    if (next != NULL) {
                        next->prev = prev;
                    }

                    free(cur);
                    cur = next;
                } else if (polldata[0].revents & POLLIN) {
                    recv(cur->from_tcp_sock, &rsize, sizeof(rsize), 0);
                    recv(cur->from_tcp_sock, large, (size_t)rsize, 0);

                    hldsUdpLen = sizeof(hldsUdp);
                    rsize = sendto(cur->to_hlds_sock, large, (size_t)rsize, 0, (struct sockaddr *)&hldsUdp, hldsUdpLen);
                    if (rsize < 0) {
                        perror("sendto");
                        goto fail;
                    }
                } else if (polldata[1].revents & POLLIN) {
                    tmpAddressLen = sizeof(tmpAddress);
                    rsize = recvfrom(cur->to_hlds_sock, large, sizeof(large), 0, (struct sockaddr *)&tmpAddress, &tmpAddressLen);
                    if (rsize < 0) {
                        perror("recvfrom");
                        goto fail;
                    }

                    send(cur->from_tcp_sock, &rsize, sizeof(rsize), 0);
                    rsize = send(cur->from_tcp_sock, large, (size_t)rsize, 0);
                    if (rsize < 0) {
                        perror("send");
                        goto fail;
                    }
                }
            }
        }
    }

    ec = EXIT_SUCCESS;

fail:
    printf("Shutting down...\n");

    for (cur = head; cur != NULL;) {
        if (cur->to_hlds_sock >= 0) {
            shutdown(cur->to_hlds_sock, SHUT_RDWR);
            close(cur->to_hlds_sock);
        }

        if (cur->from_tcp_sock >= 0) {
            shutdown(cur->from_tcp_sock, SHUT_RDWR);
            close(cur->from_tcp_sock);
        }

        next = cur->next;
        free(cur);
        cur = next;
    }

    if (tcpListener >= 0) {
        shutdown(tcpListener, SHUT_RDWR);
        close(tcpListener);
        tcpListener = -1;
    }

    return ec;
}
