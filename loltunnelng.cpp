#include "hansock.h"
#include <cstdio>
#include <memory.h>
#include <set>
#include <string>
#include <sstream>
#include <vector>
#include <utility>
#include <stdexcept>
#include <queue>
#include <unordered_map>

uint16_t parseport(const std::string& in) {
    auto port = std::stoul(in);
    if (port <= 1 || port >= UINT16_MAX - 1) {
        fprintf(stderr, "invalid or out of range port value %lu\n", port);
        throw std::out_of_range("port value out of range");
    }
    return (uint16_t)port;
}

std::string lowerize(std::string in) {
    // this only works for ASCII and it's fine for arguments...
    for (auto& c : in) {
        int cc = (int)(uint8_t)c;
        if (cc <= 127)
            cc = std::tolower(cc);
        // don't allow nullbytes or EOFs
        if (cc > 0 && cc <= 127)
            c = (char)(uint8_t)cc;
    }
    return in;
}

hs_address parseaddress(const std::string& in) {
    uint16_t port = 0;
    hs_address addr = { hs_address_type_unknown };
    if (in.empty())
        return addr;

    std::string addrstring = in;
    std::string portstring;
    size_t portidx = addrstring.find_last_of(':');
    if (portidx != addrstring.npos) {
        portstring = addrstring.substr(portidx + 1);
        addrstring = addrstring.substr(0, portidx);
        port = parseport(portstring);
    }

    hs_address_create_from_string(
        addrstring.empty() ? nullptr : addrstring.c_str(),
        portstring.empty() ? nullptr : portstring.c_str(),
        hs_address_type_unknown,
        hs_protocol_unknown,
        &addr);
    addr.port = port;
    hs_htons(&addr.port);
    return addr;
}

std::vector<std::string> stringsplitby(std::string in, char by) {
    std::vector < std::string> r;
    if (in.empty())
        return r;

    for (size_t idx = 0;;) {
        size_t newidx = in.find(by, idx);
        if (newidx == in.npos) {
            auto leftover = in.substr(idx);
            if (!leftover.empty())
                r.push_back(leftover);
            break;
        }

        auto subrange = in.substr(idx, newidx - idx);
        if (!subrange.empty())
            r.push_back(subrange);
        idx = newidx + 1;
    }
    return r;
}

std::set<uint16_t> parseportrange(std::string range) {
    std::set<uint16_t> r;
    if (range.empty())
        return r;

    const auto ranges = stringsplitby(range, ',');
    for (const auto& range : ranges) {
        const auto ports = stringsplitby(range, '-');
        if (ports.empty()) // empty ???
            continue;
        else if (ports.size() == 1) // once
            r.insert(parseport(ports[0]));
        else { // 111-123 range
            uint16_t a = parseport(ports[0]), b = parseport(ports[1]);
            for (uint16_t from = std::min(a, b); from <= std::max(a, b); ++from) {
                r.insert(from);
            }
        }
    }
    return r;
}

std::unordered_map<uint16_t, uint16_t> parseportmap(std::string mapping) {
    std::unordered_map<uint16_t, uint16_t> r;
    if (mapping.empty())
        return r;

    const auto maps = stringsplitby(mapping, ',');
    for (const auto& m : maps) {
        const auto ports = stringsplitby(m, '=');
        if (ports.size() != 2)
            continue;
        const auto rangea = stringsplitby(ports[0], '-');
        const auto rangeb = stringsplitby(ports[1], '-');
        if (rangea.size() != rangeb.size())
            continue;
        if (rangea.size() >= 2) {
            uint16_t
                afrom = std::min(parseport(rangea[0]), parseport(rangea[1])),
                ato   = std::max(parseport(rangea[0]), parseport(rangea[1]));
            uint16_t
                bfrom = std::min(parseport(rangeb[0]), parseport(rangeb[1])),
                bto   = std::max(parseport(rangeb[0]), parseport(rangeb[1]));
            for (uint16_t from = afrom, to = bfrom; from <= std::min(ato, bto); ++from, ++to) {
                r.insert({ from, to });
            }
        }
        else if (rangea.size() == 1) {
            r.insert({ parseport(rangea[0]), parseport(rangeb[0]) });
        }
        /* else... empty? lol */
    }

    return r;
}

int printhelp() {
    printf(
        "loltunnel-ng (nkrapivindev.ru): spiritual continuation of loltunnel\n"
        "powered by the Lazy Students Gaming Association\n\nUsage:\n"
        "student mode:\n"
        "  --student\n"
        "  --ports portX-portY,port1,port2,portN\n"
        "  --to    realip:realport\n"
        "  --via   socks5ip:socks5port\n"
        "  --remap from1=to1,fromN=toN,fromX-fromY=toX-toY\n"
        "server mode:\n"
        "  --server\n"
        "  --on realport\n\n"
        "where socks5ip:socks5port are your SSH tunnel creds\n"
        "where realip:realport are *usually* 127.0.0.1 and the TCP listener port of loltunnel-ng in server mode\n"
        "where portX-portY is port range syntax (always inclusive)\n"
        "where multiple --ports arguments can be specified, will use as many UDP ports as possible\n"
    );
    return 1; // no arguments specified...?
}

hs_result blockingconnect(hs_hsocket sck, const hs_address* addr) {
    hs_result r;
    r = hs_socket_connect(addr, sck);
    if (r == hs_result_pending) {
        for (;;) {
            hs_poll_data pdata[] = { {
                sck,
                hs_event_out
            } };
            /* a timeout just to not spinlock constantly */
            r = hs_socket_poll(pdata, 1, 3000);
            if (r != hs_result_ok)
                return r;
            if (pdata[0].inout_events & (hs_event_err | hs_event_hup | hs_event_nval))
                return hs_result_oserror;
            if (pdata[0].inout_events & hs_event_out)
                return hs_result_ok;
            /* huh? okay poll again then... */
        }
    }
    return r;
}

/* mustrecv can be 0 if it's just a read operation, or >0 if a required amount of bytes is needed */
hs_result blockingtcprecv(hs_hsocket sck, std::vector<uint8_t> &buf, size_t mustrecv) {
    hs_result r = hs_result_ok;
    if (mustrecv == 0) {
        /* read until async pending */
        std::vector<uint8_t> large(65539, 0);
        for (;;) {
            size_t got = 0;
            r = hs_socket_receive(
                large.data(),
                large.size(),
                &got,
                nullptr,
                sck);
            if (r == hs_result_ok) {
                if (got == 0) {
                    r = hs_result_oserror;
                    break;
                }
                buf.insert(buf.end(), large.begin(), large.begin() + got);
            }
            else if (r == hs_result_pending) {
                r = hs_result_ok;
                break;
            }
            else {
                break;
            }
        }
    }
    else {
        std::vector<uint8_t> tmp(mustrecv, 0);
        size_t offset = 0;
        for (;;) {
            if (offset == mustrecv) {
                r = hs_result_ok;
                break;
            }
            size_t got = 0;
            r = hs_socket_receive(
                tmp.data() + offset,
                tmp.size() - offset,
                &got,
                nullptr,
                sck);
            if (r == hs_result_ok) {
                if (got == 0) {
                    r = hs_result_oserror;
                    break;
                }
                offset += got;
            }
            else if (r == hs_result_pending) {
                continue;
            }
            else {
                break;
            }
        }
        if (offset > 0) {
            buf.insert(buf.end(), tmp.begin(), tmp.begin() + offset);
        }
    }
    return r;
}

hs_result blockingsend(hs_hsocket sck, const uint8_t* what, size_t len, const hs_address *addr) {
    size_t offset = 0, sent = 0;
    hs_result r;
    for (;;) {
        sent = 0;
        r = hs_socket_send(what + offset, len - offset, &sent, addr, sck);
        if (r == hs_result_ok) {
            if (sent == 0) {
                return hs_result_oserror;
            }
            offset += sent;
            if (offset == len) {
                break;
            }
        }
        else if (r == hs_result_pending) {
            /* no buffer space, try again available */
            continue;
        }
        else {
            /* failed miserably */
            break;
        }
    }
    return r;
}

const char* socks5reptostring(const uint8_t rep) {
    switch (rep) {
        case 0x00:
            return "succeeded";
        case 0x01:
            return "general SOCKS server failure";
        case 0x02:
            return "connection not allowed by ruleset";
        case 0x03:
            return "Network unreachable";
        case 0x04:
            return "Host unreachable";
        case 0x05:
            return "Connection refused";
        case 0x06:
            return "TTL expired";
        case 0x07:
            return "Command not supported";
        case 0x08:
            return "Address type not supported";
        /* loltunnel extensions: */
        case 0xFF - 1:
            return "invalid SOCKS version";
        case 0xFF:
            return "reply recv underflow";
    }
    return "unassigned (unknown)";
}

hs_result handlesocks5cmd(hs_hsocket sck, uint8_t &rep, hs_address &out_bndaddr, std::string &out_domain) {
    std::vector<uint8_t> buff;
    hs_result r;
    size_t oldsize = 0, got = 0;
    rep = 0xFF; /* failed to get at least 4 bytes */
    // 1ver + 1rep + 1rsv + 1atyp + 2bnd.port
    r = blockingtcprecv(sck, buff, 4);
    if (r != hs_result_ok || buff.size() < 4)
        return hs_result_oserror;
    rep = 0xFF - 1; /* got invalid SOCKS version */
    if (buff[0] != 0x05)
        return hs_result_oserror;
    rep = buff[1]; /* have an actual REP from server */
    if (buff[1] != 0x00 /* succeeded */)
        return hs_result_oserror;
    switch (buff[3]) {
        default: {
            return hs_result_oserror;
        }
        case 0x01: {
            oldsize = buff.size();
            r = blockingtcprecv(sck, buff, 4 + 2);
            got = buff.size() - oldsize;
            if (r != hs_result_ok || got != 4 + 2)
                return hs_result_oserror;
            out_bndaddr = {
                hs_address_type_ipv4,
                *(uint16_t*)&buff[4 + 4]
            };
            out_bndaddr.addr.ipv4u32 = *(uint32_t*)&buff[4];
            break;
        }
        case 0x03: {
            oldsize = buff.size();
            r = blockingtcprecv(sck, buff, 1);
            got = buff.size() - oldsize;
            if (r != hs_result_ok || got != 1)
                return hs_result_oserror;
            uint8_t domlen = buff[4];
            if (domlen == 0)
                return hs_result_oserror;
            oldsize = buff.size();
            r = blockingtcprecv(sck, buff, domlen + 2);
            got = buff.size() - oldsize;
            if (r != hs_result_ok || got != domlen + 2)
                return hs_result_oserror;
            out_domain.resize(domlen);
            memcpy((char*)out_domain.data(), &buff[4 + 1], domlen);
            out_bndaddr = {
                hs_address_type_ipv4,
                *(uint16_t*)&buff[4 + domlen]
            };
            // don't set addr, use out_domain instead...
            break;
        }
        case 0x04: {
            oldsize = buff.size();
            r = blockingtcprecv(sck, buff, 16 + 2);
            got = buff.size() - oldsize;
            if (r != hs_result_ok || got != 16 + 2)
                return hs_result_oserror;
            out_bndaddr = {
                hs_address_type_ipv6,
                *(uint16_t*)&buff[4 + 16]
            };
            memcpy(out_bndaddr.addr.ipv6u8, &buff[4], sizeof(out_bndaddr.addr.ipv6u8));
            break;
        }
    }
    /* weird quirk, some SOCKS5 servers pad their replies */
    /* need to read until the REAL END of the TCP stream */
    // r = blockingtcprecv(sck, buff, 0);
    return r;
}

hs_result sendsocks5cmd(hs_hsocket sck, uint8_t ucmd, const hs_address &addr, const std::string& domain) {
    std::vector<uint8_t> buff;
    buff.push_back(0x05); // VER
    buff.push_back(ucmd); // CMD
    buff.push_back(0x00); // RSV
    switch (addr.type) {
        default: {
            if (domain.empty() || domain.size() > 0xFF) {
                return hs_result_invarg;
            }
            else {
                buff.push_back(0x03); // ATYP DOMAINNAME
                // DST.ADDR DOMAINNAME:
                buff.insert(buff.end(), (const uint8_t*)domain.c_str(), ((const uint8_t*)domain.c_str()) + domain.size());
            }
            break;
        }
        case hs_address_type_ipv4: {
            buff.push_back(0x01); // ATYP IPv4
            // DST.ADDR IPv4:
            buff.insert(buff.end(), std::begin(addr.addr.ipv4u8), std::end(addr.addr.ipv4u8));
            break;
        }
        case hs_address_type_ipv6: {
            buff.push_back(0x04); // ATYP IPv6
            // DST.ADDR IPv6:
            buff.insert(buff.end(), std::begin(addr.addr.ipv6u8), std::end(addr.addr.ipv6u8));
            break;
        }
    }
    // DST.PORT
    buff.insert(buff.end(), (const uint8_t*)&addr.port, ((const uint8_t*)&addr.port) + sizeof(addr.port));
    return blockingsend(sck, buff.data(), buff.size(), nullptr);
}

struct clientdgram {
    uint16_t sender, receiver;
    std::vector<uint8_t> what;

    clientdgram() :
        sender(0), receiver(0) {
    }

    clientdgram(uint16_t sndr, uint16_t rcvr) :
        sender(sndr), receiver(rcvr) {
    }

    std::vector<uint8_t> torawbytes() const {
        std::vector<uint8_t> raw(
            sizeof(sender) + sizeof(receiver) + sizeof(uint32_t) + what.size(),
            0
        );
        memcpy(raw.data(), &sender, sizeof(sender));
        memcpy(raw.data() + sizeof(sender), &receiver, sizeof(receiver));
        auto size = static_cast<uint32_t>(what.size());
        auto sizele = size;
        hs_htonl(&size);
        memcpy(raw.data() + sizeof(sender) + sizeof(receiver), &size, sizeof(size));
        if (sizele > 0) {
            memcpy(
                raw.data() + sizeof(sender) + sizeof(receiver) + sizeof(size),
                what.data(),
                what.size());
        }
        return raw;
    }
};

int studentloop(
    const std::vector<uint16_t> &whichports,
    const hs_address &socks5addr,
    const hs_address &srvaddr,
    const std::unordered_map<uint16_t, uint16_t> &portmap
) {
    int run = 1;
    int havesocks = 0;
    hs_result hsr = hs_result_ok;
    hs_hsocket hsocks = hs_invalid_hsocket;
    std::vector<uint8_t> buf;
    std::vector<uint8_t> dgrambuf(65539, 0);

    /* reverse port mapping */
    std::unordered_map<uint16_t, uint16_t> rportmap;
    for (const auto& kvp : portmap) {
        rportmap.insert({ kvp.second, kvp.first });
        printf("map UDP port %d to %d\n", int(kvp.first), int(kvp.second));
    }

    struct clientextradata {
        std::queue<clientdgram> dgramqueue;
        hs_address bindaddr = { }, lastaddr = {};
    };

    std::vector<uint8_t> outqueue;

    std::vector<hs_poll_data> udplisteners;
    std::vector<clientextradata> udpstuff;

    for (const auto& port : whichports) {
        hs_address localaddr = { hs_address_type_unknown };
        hsr = hs_address_create(hs_address_init_ipv4_loopback, port, &localaddr);
        if (hsr != hs_result_ok) {
            fprintf(stderr, "failed to create localhost udp addr for %d\n", (int)port);
            return 1;
        }

        hs_hsocket udpsock = hs_invalid_hsocket;
        hsr = hs_socket_create(hs_af_inet, hs_type_dgram, hs_protocol_udp, &udpsock);
        if (hsr != hs_result_ok) {
            fprintf(stderr, "failed to create udp localhost socket\n");
            return 1;
        }

        hsr = hs_socket_feature(hs_feature_nonblocking, true, udpsock);
        if (hsr != hs_result_ok) {
            fprintf(stderr, "failed to enable udp nonblocking\n");
            return 1;
        }

        hsr = hs_socket_feature(hs_feature_reuseaddr, true, udpsock);
        if (hsr != hs_result_ok) {
            fprintf(stderr, "failed to enable udp reuseaddr\n");
            return 1;
        }

        hsr = hs_socket_bind(&localaddr, udpsock);
        if (hsr != hs_result_ok) {
            fprintf(stderr, "failed to bind udp on port %d\n", int(port));
            return 1;
        }

        hs_poll_data polltmpdat = { udpsock, hs_event_unknown };
        udplisteners.push_back(polltmpdat);
        clientextradata extradata;
        extradata.bindaddr = localaddr;
        udpstuff.push_back(extradata);

        printf("created UDP socket on port %d\n", int(port));
    }

    // reserve space for the socks5 socket at the back
    udplisteners.push_back({ hs_invalid_hsocket, hs_event_unknown });

    while (run) {
        // enter a sorta-blocking socks5 connect loop
        if (!havesocks) {
            if (hsocks != hs_invalid_hsocket) {
                hs_socket_close(hsocks);
                hsocks = hs_invalid_hsocket;
            }

            hsr = hs_socket_create((hs_af)socks5addr.type, hs_type_stream, hs_protocol_tcp, &hsocks);
            if (hsr != hs_result_ok) {
                fprintf(stderr, "socks5 failed socket create\n");
                break;
            }

            hsr = hs_socket_feature(hs_feature_nonblocking, 1, hsocks);
            if (hsr != hs_result_ok) {
                fprintf(stderr, "socks5 failed nonblock mode\n");
                break;
            }

            hsr = blockingconnect(hsocks, &socks5addr);
            if (hsr != hs_result_ok) {
                fprintf(stderr, "connection failed, retrying...\n");
                continue;
            }

            printf("connected, sending socks5 hello...\n");
            uint8_t sockshi[] = {
                0x05, /* VERSION */
                0x01, /* NMETHODS */
                0x00  /* METHOD: No authentication required */
            };
            hsr = blockingsend(hsocks, sockshi, sizeof(sockshi), nullptr);
            if (hsr != hs_result_ok) {
                fprintf(stderr, "failed to send socks5 hello\n");
                continue;
            }

            printf("sent, waiting for methods reply...\n");
            buf.clear();
            hsr = blockingtcprecv(hsocks, buf, 2);
            if (hsr != hs_result_ok || buf.size() != 2) {
                fprintf(stderr, "failed to recv supported method\n");
                continue;
            }

            if (buf[0] != 0x05 || buf[1] != 0x00) {
                fprintf(stderr, "version or method invalid\n");
                continue;
            }

            hsr = sendsocks5cmd(hsocks, 0x01, srvaddr, std::string());
            if (hsr != hs_result_ok) {
                fprintf(stderr, "failed to send socks5 connect cmd\n");
                continue;
            }

            uint8_t rep = 0;
            hs_address bndaddr = { hs_address_type_unknown };
            std::string bnddom;
            hsr = handlesocks5cmd(hsocks, rep, bndaddr, bnddom);
            if (hsr != hs_result_ok) {
                fprintf(stderr, "socks5 connect failed with REP=0x%02X,%s\n",
                    (unsigned)rep,
                    socks5reptostring(rep));
                continue;
            }

            printf("socks5 connected OK\n");
            havesocks = 1;
            udplisteners.back().in_socket = hsocks;
            buf.clear();
            outqueue.clear();
        }

        for (auto& polldat : udplisteners) {
            polldat.inout_events = (hs_event)(hs_event_out | hs_event_in);
        }

        hsr = hs_socket_poll(
            udplisteners.data(),
            udplisteners.size(),
            0);

        auto socksmask = udplisteners.back().inout_events;
        if (socksmask & (hs_event_hup | hs_event_err | hs_event_nval)) {
            havesocks = 0;
            fprintf(stderr, "socks 5 error cond, retrying...\n");
            continue;
            /* skip stuff below because it won't make any sense */
        }

        /* try to receive as many bytes as possible via TCP */
        if (socksmask & hs_event_in) {
            for (;;) {
                uint8_t b[256] = { 0 }; size_t gotb = 0;
                hsr = hs_socket_receive(b, sizeof(b), &gotb, nullptr, hsocks);
                if (gotb == 0) {
                    if (hsr == hs_result_pending)
                        /* no more bytes to receive */
                        break;
                    else {
                        havesocks = 0;
                        fprintf(stderr, "socks 5 disconnection in recv, retrying...\n");
                        break;
                    }
                }
                buf.insert(buf.end(), &b[0], &b[gotb]);
            }
        }

        /* try to send as many datagrams to SOCKS TCP out as possible */
        if (socksmask & hs_event_out) {
            for (;;) {
                if (outqueue.empty())
                    break;
                size_t sent = 0;
                hsr = hs_socket_send(
                    outqueue.data(),
                    std::min<size_t>(outqueue.size(), 512),
                    &sent,
                    nullptr,
                    hsocks);
                if (sent > 0) {
                    outqueue.erase(outqueue.begin(), outqueue.begin() + sent);
                }
                else {
                    if (hsr != hs_result_pending) {
                        havesocks = 0; /* socket died */
                    }
                    break;
                }
            }
        }

        /* process as many bytes as possible */
        for (;;) {
            size_t buflen = buf.size();
            const size_t pkthdrlen = (sizeof(uint16_t) * 2) + sizeof(uint32_t);
            if (buflen >= pkthdrlen) {
                uint32_t udplen = *(uint32_t*)(buf.data() + (sizeof(uint16_t) * 2));
                hs_htonl(&udplen);
                if (buflen >= pkthdrlen + udplen) {
                    clientdgram indgram(
                        *(uint16_t*)buf.data(),
                        *(uint16_t*)(buf.data() + sizeof(uint16_t))
                    );
                    if (udplen > 0) {
                        indgram.what.insert(
                            indgram.what.end(),
                            buf.begin() + pkthdrlen,
                            buf.begin() + pkthdrlen + udplen);
                    }
                    /* ok, parsed a full dgram, crop the buffer */
                    buf.erase(buf.begin(), buf.begin() + pkthdrlen + udplen);
                    /* figure out in which queue to put it... */
                    uint16_t leport = indgram.receiver;
                    hs_htons(&leport);
                    /* also go through port remap */
                    const auto it = rportmap.find(leport);
                    if (it != rportmap.end()) {
                        leport = it->second;
                        indgram.receiver = leport;
                        hs_htons(&indgram.receiver);
                    }
                    for (size_t idx = 0; idx < whichports.size(); ++idx) {
                        if (whichports.at(idx) == leport) {
                            udpstuff.at(idx).dgramqueue.push(indgram);
                        }
                    }
                }
                else break;
            }
            else break;
        }

        /* process as many incoming datagrams as possible */
        for (size_t idx = 0; idx < whichports.size(); ++idx) {
            auto& pollpair = udplisteners.at(idx);
            /* pump datagrams into queues */
            for (;;) {
                bool havedata = pollpair.inout_events & hs_event_in;
                if (!havedata)
                    break;
                hs_address dgramwho = { hs_address_type_unknown };
                size_t dgramgot = 0;
                // dgrambuf is a fixed 65539 bytes vector
                hsr = hs_socket_receive(
                    dgrambuf.data(),
                    dgrambuf.size(),
                    &dgramgot,
                    &dgramwho,
                    pollpair.in_socket);
                if (dgramgot == 0) {
                    if (hsr == hs_result_pending)
                        /* out of datagrams to recv */
                        break;
                    else if (hsr != hs_result_ok) {
                        fprintf(stderr, "error condition on UDP socket!!?\n");
                        break;
                    }
                }
                udpstuff.at(idx).lastaddr = dgramwho;
                /* forward to the TCP SOCKS socket even if got==0 */
                clientdgram tmpdgram(dgramwho.port, udpstuff.at(idx).bindaddr.port);
                if (dgramgot > 0) {
                    tmpdgram.what.insert(
                        tmpdgram.what.end(),
                        dgrambuf.begin(),
                        dgrambuf.begin() + dgramgot);
                }
                uint16_t leport = tmpdgram.receiver;
                hs_htons(&leport);
                const auto it = portmap.find(leport);
                if (it != portmap.end()) {
                    /* this port should be remapped */
                    leport = it->second;
                    tmpdgram.receiver = leport;
                    hs_htons(&tmpdgram.receiver);
                }
                auto rawtmp(tmpdgram.torawbytes());
                outqueue.insert(outqueue.end(), rawtmp.begin(), rawtmp.end());
            }
            /* push datagrams from queues */
            for (;;) {
                bool havesend = pollpair.inout_events & hs_event_out;
                if (!havesend) {
                    break;
                }
                const auto& lastadr = udpstuff.at(idx).lastaddr;
                if (lastadr.port == 0) {
                    break;
                }
                auto& q = udpstuff.at(idx).dgramqueue;
                if (q.empty()) {
                    break;
                }
                auto& qd = q.front();
                size_t qsent = 0;
                hsr = hs_socket_send(
                    qd.what.data(),
                    qd.what.size(),
                    &qsent,
                    &lastadr, /* ?????????????????????? */
                    pollpair.in_socket);
                if (hsr == hs_result_pending) {
                    break;
                }
                q.pop();
            }
        }
    }

    return 0;
}

struct serverclient {
    hs_hsocket tcpsocket;
    hs_address tcpaddress; /* who connected? */
    std::unordered_map<uint16_t, std::queue<clientdgram>> udpqueues;
    std::unordered_map<uint16_t, hs_hsocket> udpsockets;
    std::vector<uint8_t> tcpbuffer; /* for INCOMING data */
    std::vector<uint8_t> tcpoutbuffer; /* for OUTCOMING (to SOCKS side) data */
    bool getridof = false; /* deallocate on next iteration? */
};

int serverloop(uint16_t onport) {
    std::vector<uint8_t> large(65539, 0);
    std::vector<hs_poll_data> polls;
    std::vector<serverclient> clients;

    hs_hsocket fromsocks;
    hs_address fromsocksaddr;
    hs_result hsr;
    hsr = hs_address_create(hs_address_init_ipv4_loopback, onport, &fromsocksaddr);
    if (hsr != hs_result_ok) {
        fprintf(stderr, "failed to create loopback address\n");
        return 1;
    }
    hsr = hs_socket_create(hs_af_inet, hs_type_stream, hs_protocol_tcp, &fromsocks);
    if (hsr != hs_result_ok) {
        fprintf(stderr, "failed to create TCP listener sock\n");
        return 1;
    }
    hsr = hs_socket_feature(hs_feature_nonblocking, 1, fromsocks);
    if (hsr != hs_result_ok) {
        fprintf(stderr, "failed to enable nonblocking mode\n");
        return 1;
    }
    hsr = hs_socket_feature(hs_feature_reuseaddr, 1, fromsocks);
    if (hsr != hs_result_ok) {
        fprintf(stderr, "failed to enable reuseaddr\n");
        return 1;
    }
    hsr = hs_socket_bind(&fromsocksaddr, fromsocks);
    if (hsr != hs_result_ok) {
        fprintf(stderr, "bind failed\n");
        return 1;
    }
    hsr = hs_socket_listen(-1, fromsocks);
    if (hsr != hs_result_ok) {
        fprintf(stderr, "listen failed\n");
        return 1;
    }
    polls.push_back({ fromsocks, hs_event_unknown });

    printf("entering server loop listening on %d...\n", int(onport));

    while (true) {
        for (auto ci = 0ll; ci < clients.size(); ++ci) {
            if (clients.at(ci).getridof) {
                char addrstr[64] = { 0 };
                hsr = hs_address_to_string(addrstr, sizeof(addrstr), &clients.at(ci).tcpaddress);
                for (auto pi = 0ll; pi < polls.size(); ++pi) {
                    if (clients.at(ci).tcpsocket == polls.at(pi).in_socket) {
                        printf("deallocating TCP socket for client %s\n", addrstr);
                        hsr = hs_socket_close(polls.at(pi).in_socket);
                        polls.erase(polls.begin() + pi);
                        --pi; continue;
                    }

                    for (const auto& kvp : clients.at(ci).udpsockets) {
                        if (kvp.second == polls.at(pi).in_socket) {
                            printf("deallocating UDP %d socket for client %s\n", int(kvp.first), addrstr);
                            hsr = hs_socket_close(kvp.second);
                            polls.erase(polls.begin() + pi);
                            --pi; break;
                        }
                    }
                }
                printf("client %s deallocated\n", addrstr);
                clients.erase(clients.begin() + ci);
                --ci;
            }
        }

        for (auto& poll : polls)
            poll.inout_events = (hs_event)(hs_event_in | hs_event_out);
        hsr = hs_socket_poll(polls.data(), polls.size(), 0);

        const auto srvmask = polls.at(0).inout_events;
        if (srvmask & hs_event_in) {
            hs_address newcliaddr;
            hs_hsocket newclisock;
            hsr = hs_socket_accept(&newcliaddr, &newclisock, fromsocks);
            if (hsr == hs_result_ok) {
                hs_socket_feature(hs_feature_nonblocking, 1, newclisock);
                char addrstr[64] = { 0 };
                hsr = hs_address_to_string(addrstr, sizeof(addrstr), &newcliaddr);
                printf("accepted new connection from %s\n", addrstr);
                serverclient scli = { newclisock, newcliaddr };
                clients.push_back(scli);
                polls.push_back({ newclisock, hs_event_unknown });
            }
        }

        for (size_t ci = 0; ci < clients.size(); ++ci) {
            char cliaddrstr[64] = { 0 };
            auto& cli = clients.at(ci);
            if (cli.getridof)
                continue;
            hsr = hs_address_to_string(cliaddrstr, sizeof(cliaddrstr), &cli.tcpaddress);
            hs_event pollmask = hs_event_unknown;
            for (size_t pi = 0; pi < polls.size(); ++pi) {
                if (polls.at(pi).in_socket == cli.tcpsocket) {
                    pollmask = polls.at(pi).inout_events;
                    break;
                }
            }

            if (pollmask & (hs_event_err | hs_event_hup | hs_event_nval)) {
                cli.getridof = true;
                printf("client %s TCP error condition\n", cliaddrstr);
                continue;
            }

            for (;;) {
                bool canrecv = pollmask & hs_event_in;
                if (!canrecv)
                    break;
                size_t got = 0;
                hsr = hs_socket_receive(
                    large.data(),
                    large.size(),
                    &got,
                    nullptr,
                    cli.tcpsocket);
                if (hsr == hs_result_ok) {
                    if (got > 0) {
                        cli.tcpbuffer.insert(
                            cli.tcpbuffer.end(),
                            large.begin(),
                            large.begin() + got);
                    }
                    else {
                        cli.getridof = true;
                        printf("client %s TCP recv got 0\n", cliaddrstr);
                        break;
                    }
                }
                else if (hsr == hs_result_pending) {
                    /* no more bytes left */
                    break;
                }
                else {
                    cli.getridof = true;
                    printf("client %s TCP recv err hansock result\n", cliaddrstr);
                    break;
                }
            }

            if (cli.getridof)
                continue;

            for (;;) {
                bool cansend = pollmask & hs_event_out;
                if (!cansend)
                    break;
                if (cli.tcpoutbuffer.empty())
                    break;
                size_t gotout = 0;
                hsr = hs_socket_send(
                    cli.tcpoutbuffer.data(),
                    std::min<size_t>(cli.tcpoutbuffer.size(), 512),
                    &gotout,
                    nullptr,
                    cli.tcpsocket);
                if (hsr == hs_result_pending)
                    break;
                else if (hsr != hs_result_ok || gotout == 0) {
                    cli.getridof = true;
                    printf("client %s TCP send is fail or 0 sent\n", cliaddrstr);
                    break;
                }
                cli.tcpoutbuffer.erase(
                    cli.tcpoutbuffer.begin(),
                    cli.tcpoutbuffer.begin() + gotout);
            }

            if (cli.getridof)
                continue;

            for (;;) {
                size_t clibuflen = cli.tcpbuffer.size();
                const size_t pktsize = (sizeof(uint16_t) * 2 + sizeof(uint32_t));
                if (clibuflen >= pktsize) {
                    uint32_t pktlen = *(uint32_t*)(cli.tcpbuffer.data() + (sizeof(uint16_t) * 2));
                    hs_htonl(&pktlen);
                    if (clibuflen >= pktsize + pktlen) {
                        uint16_t senderport = *(uint16_t*)cli.tcpbuffer.data();
                        uint16_t receiverport = *(uint16_t*)(cli.tcpbuffer.data() + sizeof(uint16_t));
                        uint16_t leport = receiverport;
                        hs_htons(&leport);
                        clientdgram indgram(senderport, receiverport);
                        if (pktlen > 0) {
                            indgram.what.insert(
                                indgram.what.end(),
                                cli.tcpbuffer.begin() + pktsize,
                                cli.tcpbuffer.begin() + pktsize + pktlen);
                        }
                        const auto it = cli.udpsockets.find(leport);
                        if (it == cli.udpsockets.end()) {
                            hs_hsocket newudpsck;
                            printf("allocating new %d port UDP socket for %s\n", int(leport), cliaddrstr);
                            hsr = hs_socket_create(hs_af_inet, hs_type_dgram, hs_protocol_udp, &newudpsck);
                            hsr = hs_socket_feature(hs_feature_nonblocking, 1, newudpsck);
                            cli.udpsockets.insert({ leport, newudpsck });
                            cli.udpqueues.insert({ leport, { } });
                            polls.push_back({ newudpsck, hs_event_unknown });
                        }
                        cli.udpqueues.at(leport).push(indgram);
                        cli.tcpbuffer.erase(cli.tcpbuffer.begin(), cli.tcpbuffer.begin() + pktsize + pktlen);
                    }
                    else break;
                }
                else break;
            }

            if (cli.getridof)
                continue;

            auto& udpclis = cli.udpsockets;
            for (const auto& kvp : udpclis) {
                uint16_t leport = kvp.first;
                uint16_t beport = leport;
                hs_htons(&beport);
                hs_hsocket usock = kvp.second;
                hs_event upollmask = hs_event_unknown;
                for (size_t pi = 0; pi < polls.size(); ++pi) {
                    if (polls.at(pi).in_socket == usock) {
                        upollmask = polls.at(pi).inout_events;
                        break;
                    }
                }

                if (upollmask & hs_event_out) {
                    auto& q = cli.udpqueues.at(leport);
                    for (;;) {
                        if (q.empty())
                            break;
                        const auto& qd = q.front();
                        /* send to our localhost but different port, on UDP */
                        hs_address to = fromsocksaddr;
                        to.port = qd.receiver;
                        size_t qsent = 0;
                        hsr = hs_socket_send(
                            qd.what.data(),
                            qd.what.size(),
                            &qsent,
                            &to,
                            usock);
                        if (hsr == hs_result_pending || hsr != hs_result_ok)
                            break; /* try later */
                        q.pop();
                    }
                }

                if (upollmask & hs_event_in) {
                    for (;;) {
                        hs_address udpfrom = { hs_address_type_unknown };
                        size_t ugot = 0;
                        hsr = hs_socket_receive(
                            large.data(),
                            large.size(),
                            &ugot,
                            &udpfrom,
                            usock);
                        if (ugot == 0) {
                            if (hsr == hs_result_pending)
                                break; /* no more datagrams */
                            else if (hsr != hs_result_ok) {
                                fprintf(stderr, "error condition on UDP %d for %s\n", int(leport), cliaddrstr);
                                break;
                            }
                        }

                        clientdgram indgram(udpfrom.port, beport);
                        if (ugot > 0) {
                            indgram.what.insert(
                                indgram.what.end(),
                                large.begin(),
                                large.begin() + ugot);
                        }
                        const auto indgrambytes(indgram.torawbytes());
                        cli.tcpoutbuffer.insert(
                            cli.tcpoutbuffer.end(),
                            indgrambytes.begin(),
                            indgrambytes.end());
                    }
                }
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (hs_init() != hs_result_ok) {
        printf("hansock init fail, wtf?!\n");
        return 1;
    }

    uint16_t defsocks5port = 1080;
    /* https://datatracker.ietf.org/doc/html/rfc1928 */
    hs_htons(&defsocks5port);
    std::unordered_map<uint16_t, uint16_t> portmap;
    std::set<uint16_t> udpports;
    uint16_t onport = 0;
    bool student = true;
    hs_address socks5addr = { hs_address_type_unknown };
    hs_address srvaddr = { hs_address_type_unknown };

    if (argc <= 1) {
        return printhelp();
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i], nextarg;
        // most options use this anyway...
        if (i < argc - 1)
            nextarg = argv[i + 1];

        arg = lowerize(arg);
        if (arg == "--ports") {
            // parse port range string...
            auto newrange = parseportrange(nextarg);
            udpports.insert(newrange.begin(), newrange.end());
            ++i; continue;
        }
        else if (arg == "--on") {
            onport = parseport(nextarg);
            ++i; continue;
        }
        else if (arg == "--server") {
            student = false;
            continue; // doesn't use nextarg
        }
        else if (arg == "--student") {
            student = true;
            continue; // doesn't use nextarg
        }
        else if (arg == "--remap") {
            auto newports = parseportmap(nextarg);
            portmap.insert(newports.begin(), newports.end());
            ++i; continue;
            /* for local testing only! */
            /* remap 27015 to 27016 to avoid conflicts */
        }
        else if (arg == "--via") {
            socks5addr = parseaddress(nextarg);
            /* in case port was unspecified */
            if (socks5addr.port == 0)
                socks5addr.port = defsocks5port;
            ++i; continue;
        }
        else if (arg == "--to") {
            srvaddr = parseaddress(nextarg);
            ++i; continue;
        }
        else if (arg == "--help" || arg == "-h") {
            return printhelp();
        }
    }

    if (student)
        return studentloop(std::vector<uint16_t>(udpports.begin(), udpports.end()), socks5addr, srvaddr, portmap);
    else
        return serverloop(onport);
}
