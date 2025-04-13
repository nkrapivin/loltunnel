# loltunnel-ng

The software I use to bypass hanriel's dumb and idiotic firewall at the wonderful [Perm Engineering College](https://pmkspo.ru/)

Powered by the cross-platform Hansock&trade; socket library!

***Нахуй фаерволлы! Свободу студентам! Контер-Страйк сила!***

*PS: может закроете мне долг по матеше за второй курс? я тупой и матан не знаю, могу вон тока на крестах кросс-платформенно говнокодить... pretty pwease*

## Prereqs

A somewhat modern Linux machine with some C and C++ compilers installed (GCC or Clang).

Tested on RED OS 8 Desktop Edition, Xubuntu 20.04 LTS and Windows 10

## How to compile

For Linux:
- use the `build.linux.sh` script

For Windows:
- build the `loltunnelng.sln` solution

For other platforms:
- make your own `hansock_$PLATFORM.c` implementation that conforms to the public header, try to make it use the most native functions your platform provides - as in, avoid any wrappers.
- make sure your platform supports argc, argv and C++ STL
- compile both `hansock_$PLATFORM.c` and `loltunnelng.cpp` against your platform's compiler
- run the binary and see if it blows up

## How to use

### Server setup

- Figure out which UDP ports your game is using
- Run loltunnel with `--server --on $REALPORT`:
- where `$REALPORT` is any port that's free for localhost

### Student setup (SSH SOCKS 5)

- On student machines that wish to play a game instead of listening to the lecture, run:
- an SSH tunnel via `ssh -D 127.0.0.1:$NPPORT -N $STUDENTUSER@$STUDENTDOMAINNAME`
- where `$NPPORT` is any non-privileged port that you can use for binding to localhost
- where `$STUDENTUSER` is the user you can ssh as into a student PC
- where `$STUDENTDOMAINNAME` is the domain name of your machine, in the Perm Engineering College the format is:
- the first letter is `z` for workstations, `b` for laptops (notebooks - books)
- the number specifies the room (auditorija)
- after the dash, follows the seat number
- so `b383-4` is the fourth laptop in the 383 room
- Example: `ssh -D 127.0.0.1:1337 -N s13423@b383-4`
- will spawn a localhost tunnel on port 1337 to a 4th laptop in room 383 as `s13423` (Krapivin Nikita Andreevich)

### Student setup (LOLTunnel-NG)

- Run loltunnel with `--student --ports $PORTS --to 127.0.0.1:$REALPORT --via 127.0.0.1:$NPPORT`:
- where `$PORTS` is the UDP port range for the game
- where `$REALPORT` is the bind port of the server from the server setup guide
- where `$NPPORT` is the port used for the ssh SOCKS tunnel
- after that's done, run the game server on the server machine and try to connect to `127.0.0.1:$PORTS`

## How it works

The server mode waits for incoming TCP connections, reads datagrams from them ands sends them over to the UDP game server. Likewise, whenever the game server replies, the datagrams are forwarded into the TCP connection back to the client.

The student mode starts as many UDP localhost listeners as specified, forwards all datagrams to the TCP tunnel, and sends all the replies back to UDP vice-versa.

## Limitations / aka a TODO list

- Perhaps rewrite in a scripting language in case compilers get blocked (which is highly likely given the stupidity of our policies)?

## Credits / Cheerz to

- zhilemann a/k/a VeyonHater a/k/a Hrukmeister
- sleirsgoevy
- unnamed PMK students who I will not name to save their souls from the very evil sysadmins

