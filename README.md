# loltunnel

The software I use to bypass hanriel's dumb and idiotic firewall at the wonderful [Perm Engineering College](https://pmkspo.ru/)

***Нахуй фаерволлы! Свободу студентам! Контер-Страйк сила!***

## Prereqs

A somewhat modern Linux machine with some C compiler installed.

Tested on RED OS 8 Desktop Edition

## How to compile

```sh
gcc listener.c -o listener
gcc main.c -o main
```

## How to use

- Run HLDS with default settings (on UDP 27015)
- Run listener binary on the HLDS machine
- On all student (client) machines do `ssh -D 127.0.0.1:1337 -N sNUMBERS@zXXX-Y` to the HLDS machine
- Then run the main binary on all student machines
- The server hoster should `connect 127.0.0.1:27015` on their local machine and the local game client (in case they want to play)
- Students should `connect 127.0.0.1:21110` on their machines to connect to the remote HLDS server
- The above will only work *if* the SSH tunnel works *and* the main executable is running *and* the listener is running
- Enjoy! Ping will be around 120ms at best, but it's playable for CS1.6 in particular, other games are untested

## How it works

The main executable runs a localhost UDP listener at port 21110 that forwards all UDP datagrams to the SOCKS 5 server at 127.0.0.1:1337
it expects that the receiver side will forward those datagrams further to HLDS, and then send any replies from HLDS back to the other side of the socket.

The listener executable runs a normal TCP listener, forwards all incoming datagrams via locally-bound UDP sockets and sends any replies
back from the UDP sockets to the TCP socket.

## Limitations / aka a TODO list

- Make it use non-blocking sockets?
- Recover on socket failures instead of perror and exit?
- Perhaps rewrite in a scripting language in case compilers get blocked (which is highly likely given the stupidity of our policies)?

## Credits / Cheerz to

- zhilemann a/k/a VeyonHater a/k/a Hrukmeister
- unnamed PMK students who I will not name to save their souls from the very evil sysadmins

