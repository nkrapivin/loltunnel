#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <asm-generic/socket.h>
#include <memory.h>
#include <arpa/inet.h>

static uint8_t large[65536 * 2];

int main(int argc, char *argv[], char *envp[]) {
    const int one = 1;

    int ec = EXIT_FAILURE;

    struct sockaddr_in udpListenAddress = { };
    udpListenAddress.sin_family = AF_INET;
    udpListenAddress.sin_port = htons(21110);
    udpListenAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    struct sockaddr_in udpFromAddress = { };
    udpFromAddress.sin_family = AF_INET;
    socklen_t udpFromLen = sizeof(udpFromAddress);

    struct sockaddr_in socksProxyAddress = { };
    socksProxyAddress.sin_family = AF_INET;
    socksProxyAddress.sin_port = htons(1337);
    socksProxyAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    struct sockaddr_in listenerAddress = { };
    listenerAddress.sin_family = AF_INET;
    listenerAddress.sin_port = htons(27220);
    listenerAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    struct pollfd polldata[2] = { };
    ssize_t rsize = 0;

    uint8_t tmp[2048] = { 0x05, 0x01, 0x00 };

    int socksSocket = -1, udpSocket = -1, r = 0, run = 1;

    printf("Setting up SOCKS5 client...\n");
    socksSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (socksSocket < 0) {
        perror("socket");
        goto fail;
    }

    if (setsockopt(socksSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        goto fail;
    }

    if (setsockopt(socksSocket, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        goto fail;
    }

    printf("SOCKS5 connect...\n");
    if (connect(socksSocket, (struct sockaddr *)&socksProxyAddress, sizeof(socksProxyAddress)) < 0) {
        perror("connect");
        goto fail;
    }

    if (send(socksSocket, tmp, 3, 0) != 3) {
        perror("send");
        goto fail;
    }

    if (recv(socksSocket, tmp, sizeof(tmp), 0) <= 1) {
        perror("recv");
        goto fail;
    }

    if (tmp[0] != 0x05) {
        fprintf(stderr, "SOCKS version not 5\n");
        goto fail;
    }

    if (tmp[1] != 0x00) {
        fprintf(stderr, "SOCKS invalid auth method\n");
        goto fail;
    }

    printf("SOCKS 5 connect ok, sending request...\n");
    tmp[0] = 0x05;
    tmp[1] = 0x01;
    tmp[2] = 0x00;
    tmp[3] = 0x01;
    memcpy(&tmp[4], &listenerAddress.sin_addr.s_addr, sizeof(listenerAddress.sin_addr.s_addr));
    memcpy(&tmp[4 + sizeof(listenerAddress.sin_addr.s_addr)], &listenerAddress.sin_port, sizeof(listenerAddress.sin_port));
    rsize = 4 + sizeof(listenerAddress.sin_addr.s_addr) + sizeof(listenerAddress.sin_port);
    if (send(socksSocket, tmp, rsize, 0) != rsize) {
        perror("send");
        goto fail;
    }

    if (recv(socksSocket, tmp, sizeof(tmp), 0) != 10) {
        perror("recv");
        goto fail;
    }

    if (tmp[0] != 0x05) {
        fprintf(stderr, "Reply invalid socks ver\n");
        goto fail;
    }

    if (tmp[1] != 0x00) {
        fprintf(stderr, "Reply invalid field\n");
        goto fail;
    }

    if (tmp[2] != 0x00) {
        fprintf(stderr, "Reply invalid rsv\n");
        goto fail;
    }

    if (tmp[3] != 0x01) {
        fprintf(stderr, "Reply invalid atyp\n");
        goto fail;
    }

    printf("Setting up UDP...\n");
    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket < 0) {
        perror("socket");
        goto fail;
    }

    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        goto fail;
    }

    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        goto fail;
    }

    if (bind(udpSocket, (struct sockaddr *)&udpListenAddress, sizeof(udpListenAddress)) < 0) {
        perror("bind");
        goto fail;
    }

    printf("Setting up poll() structures...\n");
    polldata[0].fd = udpSocket;
    polldata[0].events = POLLIN;
    polldata[0].revents = 0;

    polldata[1].fd = socksSocket;
    polldata[1].events = POLLIN;
    polldata[1].revents = 0;

    printf("Entering main loop...\n");
    while (run) {
        polldata[0].revents = polldata[1].revents = 0;
        r = poll(polldata, sizeof(polldata) / sizeof(polldata[0]), 0);
        if (r < 0) {
            perror("poll");
            goto fail;
        }

        if (r == 0) {
            continue;
        }

        /* got POLLIN event? */
        if (polldata[0].revents & POLLIN) {
            udpFromLen = sizeof(udpFromAddress);
            rsize = recvfrom(udpSocket, large, sizeof(large), 0, (struct sockaddr *)&udpFromAddress, &udpFromLen);
            if (r < 0) {
                perror("recvfrom");
                goto fail;
            }

            send(socksSocket, &rsize, sizeof(rsize), 0);
            rsize = send(socksSocket, large, (size_t)rsize, 0);
            if (rsize < 0) {
                perror("send");
                goto fail;
            }
        } else if (polldata[1].revents & POLLIN) {
            recv(socksSocket, &rsize, sizeof(rsize), 0);
            recv(socksSocket, large, (size_t)rsize, 0);
            udpFromLen = sizeof(udpFromAddress);
            rsize = sendto(udpSocket, large, (size_t)rsize, 0, (struct sockaddr *)&udpFromAddress, udpFromLen);
            if (rsize < 0) {
                perror("sendto");
                goto fail;
            }
        }
    }

    ec = EXIT_SUCCESS;

fail:
    printf("Shutting down...\n");

    if (udpSocket >= 0) {
        shutdown(udpSocket, SHUT_RDWR);
        close(udpSocket);
        udpSocket = -1;
    }

    if (socksSocket >= 0) {
        shutdown(socksSocket, SHUT_RDWR);
        close(socksSocket);
        socksSocket = -1;
    }

    return ec;
}

