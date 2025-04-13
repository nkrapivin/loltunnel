#include "hansock.h"
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <errno.h>
#include <alloca.h>
#include <fcntl.h>
#include <unistd.h>
#include <memory.h>

static int initialized = 0;
static char rcsid[] = "hansock library, Linux implementation. (C) by nkrapivindev.ru";

/* Largest possible sockaddr structure size */
#define osaddrsize (sizeof(struct sockaddr_storage))

/* To get away with int -> ptr warnings */
#define tohsock(ValueExpr) ((hs_hsocket)(intptr_t)(ValueExpr))
#define fromhsock(ValueExpr) ((int)(intptr_t)(ValueExpr))

static hs_result hs_af_to_os_af(hs_af in_enum_value, int *out_native_value) {
	if (!out_native_value)
		return hs_result_invarg;
	*out_native_value = 0;
	switch (in_enum_value) {
	case hs_af_inet:
		*out_native_value = AF_INET;
		return hs_result_ok;
	case hs_af_inet6:
		*out_native_value = AF_INET6;
		return hs_result_ok;
	}
	return hs_result_invarg;
}

static hs_result hs_address_type_to_os_af(hs_address_type in_enum_value, int* out_native_value) {
	if (!out_native_value)
		return hs_result_invarg;
	*out_native_value = AF_UNSPEC;
	switch (in_enum_value) {
	case hs_address_type_ipv4:
		*out_native_value = AF_INET;
		return hs_result_ok;
	case hs_address_type_ipv6:
		*out_native_value = AF_INET6;
		return hs_result_ok;
	}
	return hs_result_invarg;
}

static hs_result hs_type_to_os_type(hs_type in_enum_value, int* out_native_value) {
	if (!out_native_value)
		return hs_result_invarg;
	*out_native_value = 0;
	switch (in_enum_value) {
	case hs_type_stream:
		*out_native_value = SOCK_STREAM;
		return hs_result_ok;
	case hs_type_dgram:
		*out_native_value = SOCK_DGRAM;
		return hs_result_ok;
	}
	return hs_result_invarg;
}

static hs_result hs_protocol_to_os_protocol(hs_protocol in_enum_value, int* out_native_value) {
	if (!out_native_value)
		return hs_result_invarg;
	*out_native_value = 0;
	switch (in_enum_value) {
	case hs_protocol_auto:
		/* 0 in WinSock means auto-guess based on AF+TYPE */
		return hs_result_ok;
	case hs_protocol_tcp:
		*out_native_value = IPPROTO_TCP;
		return hs_result_ok;
	case hs_protocol_udp:
		*out_native_value = IPPROTO_UDP;
		return hs_result_ok;
	}
	return hs_result_invarg;
}

static hs_result hs_os_address_to_address(struct sockaddr* in_os_address_ptr, socklen_t namelen, hs_address* out_address_ptr) {
	if (!out_address_ptr || !in_os_address_ptr || namelen <= 1)
		return hs_result_invarg;
	switch (in_os_address_ptr->sa_family) {
		default: {
			return hs_result_invarg;
		}
		case AF_INET: {
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)in_os_address_ptr;
			if (namelen < sizeof(*ipv4))
				return hs_result_invarg;
			memset(out_address_ptr, 0, sizeof(*out_address_ptr));
			out_address_ptr->type = hs_address_type_ipv4;
			out_address_ptr->port = ipv4->sin_port;
			out_address_ptr->addr.ipv4u32 = ipv4->sin_addr.s_addr;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)in_os_address_ptr;
			if (namelen < sizeof(*ipv6))
				return hs_result_invarg;
			memset(out_address_ptr, 0, sizeof(*out_address_ptr));
			out_address_ptr->type = hs_address_type_ipv6;
			out_address_ptr->port = ipv6->sin6_port;
			memcpy(out_address_ptr->addr.ipv6u8, ipv6->sin6_addr.s6_addr, sizeof(ipv6->sin6_addr.s6_addr));
			break;
		}
	}
	return hs_result_ok;
}

static hs_result hs_address_to_os_address(const hs_address* in_address_ptr, struct sockaddr* in_os_address_ptr, socklen_t *out_namelen) {
	if (!in_address_ptr || !in_os_address_ptr || !out_namelen)
		return hs_result_invarg;
	*out_namelen = 0;
	switch (in_address_ptr->type) {
		default:
			return hs_result_invarg;
		case hs_address_type_ipv4: {
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)in_os_address_ptr;
			memset(ipv4, 0, sizeof(*ipv4));
			ipv4->sin_family = AF_INET;
			ipv4->sin_port = in_address_ptr->port;
			ipv4->sin_addr.s_addr = in_address_ptr->addr.ipv4u32;
			*out_namelen = sizeof(*ipv4);
			break;
		}
		case hs_address_type_ipv6: {
			struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)in_os_address_ptr;
			memset(ipv6, 0, sizeof(*ipv6));
			ipv6->sin6_family = AF_INET6;
			ipv6->sin6_port = in_address_ptr->port;
			memcpy(ipv6->sin6_addr.s6_addr, in_address_ptr->addr.ipv6u8, sizeof(ipv6->sin6_addr.s6_addr));
			*out_namelen = sizeof(*ipv6);
			break;
		}
	}
	return hs_result_ok;
}

static hs_result hs_event_to_os_event(hs_event in_enum_value, short int *out_native_value) {
	if (!out_native_value)
		return hs_result_invarg;
	*out_native_value = 0;
	if (in_enum_value & hs_event_in)
		*out_native_value |= POLLIN;
	if (in_enum_value & hs_event_out)
		*out_native_value |= POLLOUT;
	if (in_enum_value & hs_event_pri)
		*out_native_value |= POLLPRI;
	if (in_enum_value & hs_event_err)
		*out_native_value |= POLLERR;
	if (in_enum_value & hs_event_hup)
		*out_native_value |= POLLHUP;
	if (in_enum_value & hs_event_nval)
		*out_native_value |= POLLNVAL;
	return hs_result_ok;
}

static hs_result hs_os_event_to_event(short int in_native_value, hs_event *out_enum_value) {
	if (!out_enum_value)
		return hs_result_invarg;
	*out_enum_value = hs_event_unknown;
	int val = 0;
	if (in_native_value & POLLIN)
		val |= hs_event_in;
	if (in_native_value & POLLOUT)
		val |= hs_event_out;
	if (in_native_value & POLLPRI)
		val |= hs_event_pri;
	if (in_native_value & POLLERR)
		val |= hs_event_err;
	if (in_native_value & POLLHUP)
		val |= hs_event_hup;
	if (in_native_value & POLLNVAL)
		val |= hs_event_nval;
	*out_enum_value = (hs_event)val;
	return hs_result_ok;
}

hs_result hs_init(void) {
    /* Linux doesn't seem to need any work here */
	initialized = 1;
	return hs_result_ok;
}

hs_result hs_quit(void) {
    /* This is why Linux is so based,
     * no need to de-init socket support
     */
	if (!initialized) {
		return hs_result_notinit;
	}

	initialized = 0;
	return hs_result_ok;
}

hs_result hs_socket_create(
	hs_af in_address_family,
	hs_type in_socket_type,
	hs_protocol in_socket_protocol,
	hs_hsocket* out_socket_handle
) {
	if (!initialized)
		return hs_result_notinit;
	hs_result r;
	int af, type, prot/*ogen UwU*/;
	*out_socket_handle = hs_invalid_hsocket;
	r = hs_af_to_os_af(in_address_family, &af);
	if (r)
		return r;
	r = hs_type_to_os_type(in_socket_type, &type);
	if (r)
		return r;
	r = hs_protocol_to_os_protocol(in_socket_protocol, &prot);
	if (r)
		return r;
	int sck = socket(af, type, prot);
	if (sck < 0)
		return hs_result_oserror;
	*out_socket_handle = tohsock(sck);
	return hs_result_ok;
}

hs_result hs_socket_close(hs_hsocket in_socket) {
	if (!initialized)
		return hs_result_notinit;
	if (in_socket == hs_invalid_hsocket)
		return hs_result_invarg;
	int sck = fromhsock(in_socket);
	int wsar, wsaerr;
	/* Just in case do both, to hint the OS */
	wsar = shutdown(sck, SHUT_RDWR);
	wsaerr = errno;
	wsar = close(sck);
	wsaerr = errno;
	return hs_result_ok;
}

hs_result hs_address_create(hs_address_init in_address_init, uint16_t in_port, hs_address* in_address_ptr) {
	if (!initialized)
		return hs_result_notinit;
	if (!in_address_ptr)
		return hs_result_invarg;
	switch (in_address_init) {
		default:
			return hs_result_invarg;
		case hs_address_init_ipv4_any:
		case hs_address_init_ipv4_loopback:
		case hs_address_init_ipv4_broadcast: {
			in_address_ptr->type = hs_address_type_ipv4;
			in_address_ptr->port = htons(in_port);
			uint32_t a;
			switch (in_address_init) {
				default:
					a = htonl(INADDR_ANY); break;
				case hs_address_init_ipv4_loopback:
					a = htonl(INADDR_LOOPBACK); break;
				case hs_address_init_ipv4_broadcast:
					a = htonl(INADDR_BROADCAST); break;
			}
			in_address_ptr->addr.ipv4u32 = a;
			break;
		}
		case hs_address_init_ipv6_any:
		case hs_address_init_ipv6_loopback: {
			in_address_ptr->type = hs_address_type_ipv6;
			in_address_ptr->port = htons(in_port);
			memset(in_address_ptr->addr.ipv6u8, 0, sizeof(in_address_ptr->addr.ipv6u8));
			switch (in_address_init) {
				case hs_address_init_ipv4_loopback:
					in_address_ptr->addr.ipv6u8[15] = 1; break;
			}
			break;
		}
	}
	return hs_result_ok;
}

hs_result hs_address_create_from_ipv4(uint32_t in_address, uint16_t in_port, hs_address* out_address_ptr) {
	if (!initialized)
		return hs_result_notinit;
	if (!out_address_ptr)
		return hs_result_invarg;
	memset(out_address_ptr, 0, sizeof(*out_address_ptr));
	out_address_ptr->type = hs_address_type_ipv4;
	out_address_ptr->port = htons(in_port);
	out_address_ptr->addr.ipv4u32 = htonl(in_address);
	return hs_result_ok;
}

hs_result hs_address_to_string(char* out_string, size_t in_size_of_string, const hs_address* in_address_ptr) {
	if (!initialized)
		return hs_result_notinit;
	if (!out_string || !in_address_ptr || in_size_of_string < 2)
		return hs_result_invarg;
	if (in_address_ptr->type == hs_address_type_ipv4) {
		int r = snprintf(out_string,
			in_size_of_string,
			"%d.%d.%d.%d:%d",
			(int)in_address_ptr->addr.ipv4u8[0],
			(int)in_address_ptr->addr.ipv4u8[1],
			(int)in_address_ptr->addr.ipv4u8[2],
			(int)in_address_ptr->addr.ipv4u8[3],
			(int)htons(in_address_ptr->port));
		/* just in case */
		if (r <= 1)
			return hs_result_oserror;
	}
	else if (in_address_ptr->type == hs_address_type_ipv6) {
		/* TODO! Implement! */
		return hs_result_oserror;
	}
	else {
		/* Invalid address type */
		return hs_result_invarg;
	}
	return hs_result_ok;
}

hs_result hs_socket_bind(const hs_address* in_address_ptr, hs_hsocket in_socket) {
	if (!initialized)
		return hs_result_notinit;
	if (!in_address_ptr || in_socket == hs_invalid_hsocket)
		return hs_result_invarg;
	hs_result r;
	uint8_t osaddr[osaddrsize] = { 0 };
	socklen_t osaddrlen = sizeof(osaddr);
	struct sockaddr *posaddr = (struct sockaddr*)&osaddr[0];
	r = hs_address_to_os_address(in_address_ptr, posaddr, &osaddrlen);
	if (r)
		return r;
	int sck = fromhsock(in_socket);
	int wsar = bind(sck, posaddr, osaddrlen);
	if (wsar < 0)
		return hs_result_oserror;
	return hs_result_ok;
}

hs_result hs_socket_listen(int in_backlog, hs_hsocket in_socket) {
	if (!initialized)
		return hs_result_notinit;
	if (in_socket == hs_invalid_hsocket)
		return hs_result_invarg;
	if (in_backlog < 0)
		in_backlog = SOMAXCONN;
	int sck = fromhsock(in_socket);
	int wsar = listen(sck, in_backlog);
	if (wsar < 0)
		return hs_result_oserror;
	return hs_result_ok;
}

hs_result hs_socket_send(
	const uint8_t in_data[/*in_size_of_data*/],
	size_t in_size_of_data,
	size_t* out_size_of_sent,
	/* for udp */ const hs_address* in_opt_address,
	hs_hsocket in_socket
) {
	if (!initialized)
		return hs_result_notinit;
	if (in_socket == hs_invalid_hsocket)
		return hs_result_invarg;
	hs_result r;
	uint8_t osaddr[osaddrsize] = { 0 };
	socklen_t osaddrlen = sizeof(osaddr);
	struct sockaddr* posaddr = (struct sockaddr*)&osaddr[0];
	int sck = fromhsock(in_socket);
	int wsar = 0, wsaerr = 0;
	if (out_size_of_sent)
		*out_size_of_sent = 0;
	if (in_opt_address) {
		/* UDP send */
		r = hs_address_to_os_address(in_opt_address, posaddr, &osaddrlen);
		if (r)
			return r;
		wsar = sendto(sck, in_data, in_size_of_data, 0, posaddr, osaddrlen);
		wsaerr = errno;
	}
	else {
		/* TCP send */
		wsar = send(sck, in_data, in_size_of_data, 0);
		wsaerr = errno;
	}

	if (wsar < 0) {
		if (wsaerr == EWOULDBLOCK) {
			return hs_result_pending;
		}
		return hs_result_oserror;
	}

	if (out_size_of_sent)
		*out_size_of_sent = wsar;
	return hs_result_ok;
}

hs_result hs_socket_receive(
	uint8_t out_data[/*in_size_of_data*/],
	size_t in_size_of_data,
	size_t* out_size_of_received,
	/* for udp */ hs_address* out_opt_address,
	hs_hsocket in_socket
) {
	if (!initialized)
		return hs_result_notinit;
	if (in_socket == hs_invalid_hsocket)
		return hs_result_invarg;
	uint8_t osaddr[osaddrsize] = { 0 };
	socklen_t osaddrlen = sizeof(osaddr);
	struct sockaddr* posaddr = (struct sockaddr*)&osaddr[0];
	int sck = fromhsock(in_socket);
	int wsar = 0, wsaerr = 0;
	if (out_size_of_received) {
		*out_size_of_received = 0;
	}
	if (out_opt_address) {
		/* UDP receive */
		wsar = recvfrom(sck, out_data, in_size_of_data, 0, posaddr, &osaddrlen);
		wsaerr = errno;
		(void)hs_os_address_to_address(posaddr, osaddrlen, out_opt_address);
	}
	else {
		/* TCP receive */
		wsar = recv(sck, out_data, in_size_of_data, 0);
		wsaerr = errno;
	}
	if (wsar < 0) {
		if (wsaerr == EWOULDBLOCK) {
			return hs_result_pending;
		}
		return hs_result_oserror;
	}
	if (out_size_of_received) {
		*out_size_of_received = (size_t)wsar;
	}
	return hs_result_ok;
}

hs_result hs_socket_accept(
	hs_address* out_new_address,
	hs_hsocket* out_new_socket,
	hs_hsocket in_socket
) {
	if (!initialized)
		return hs_result_notinit;
	if (in_socket == hs_invalid_hsocket)
		return hs_result_invarg;
	uint8_t osaddr[osaddrsize] = { 0 };
	socklen_t osaddrlen = sizeof(osaddr);
	struct sockaddr* posaddr = (struct sockaddr*)&osaddr[0];
	int sck = fromhsock(in_socket);
	int newsck = -1;
	int wsaerr = 0;
	*out_new_socket = hs_invalid_hsocket;
	newsck = accept(sck, posaddr, &osaddrlen);
	wsaerr = errno;
	if (newsck < 0) {
		if (wsaerr == EWOULDBLOCK) {
			return hs_result_pending;
		}
		return hs_result_oserror;
	}
	if (out_new_address) {
		hs_os_address_to_address(posaddr, osaddrlen, out_new_address);
	}
	*out_new_socket = tohsock(newsck);
	return hs_result_ok;
}

hs_result hs_socket_feature(hs_feature in_feature_type, int in_enable, hs_hsocket in_socket) {
	if (!initialized)
		return hs_result_notinit;
	if (in_socket == hs_invalid_hsocket)
		return hs_result_invarg;
	int sck = fromhsock(in_socket);
	if (in_feature_type == hs_feature_nonblocking) {
        int sckflags = fcntl(sck, F_GETFL);
        if (sckflags < 0)
            return hs_result_oserror;
        if (in_enable)
            sckflags |= O_NONBLOCK;
        else
            sckflags &= ~O_NONBLOCK;
		sckflags = fcntl(sck, F_SETFL, sckflags);
        if (sckflags < 0)
            return hs_result_oserror;
	}
	else if (in_feature_type == hs_feature_reuseaddr || in_feature_type == hs_feature_keepalive) {
		int opt = (in_feature_type == hs_feature_reuseaddr)
			? SO_REUSEADDR
			: SO_KEEPALIVE;
		int ssr = setsockopt(sck, SOL_SOCKET, opt, &in_enable, sizeof(in_enable));
		if (ssr < 0)
			return hs_result_oserror;
	}
	else {
		return hs_result_invarg;
	}
	return hs_result_ok;
}

hs_result hs_socket_connect(
	const hs_address* in_address,
	hs_hsocket in_socket
) {
	if (!initialized)
		return hs_result_notinit;
	if (!in_address || !in_socket)
		return hs_result_invarg;
	uint8_t osaddr[osaddrsize] = { 0 };
	socklen_t osaddrlen = sizeof(osaddr);
	struct sockaddr* posaddr = (struct sockaddr*)&osaddr[0];
	int sck = fromhsock(in_socket);
	hs_result r = hs_address_to_os_address(in_address, posaddr, &osaddrlen);
	if (r != hs_result_ok)
		return r;
	int wsar, wsaerr;
	wsar = connect(sck, posaddr, osaddrlen);
	wsaerr = errno;
	if (wsar < 0) {
		if (wsaerr == EWOULDBLOCK) {
			return hs_result_pending;
		}
		return hs_result_oserror;
	}
	return hs_result_ok;
}

hs_result hs_address_create_from_string(
	const char* in_opt_addr_string,
	const char* in_opt_port_string,
	hs_address_type in_opt_want_address_type,
	hs_protocol in_opt_want_protocol,
	hs_address* out_address_ptr
) {
	if (!initialized)
		return hs_result_notinit;
	if (!out_address_ptr)
		return hs_result_invarg;
	memset(out_address_ptr, 0, sizeof(*out_address_ptr));
	hs_result hsr = hs_result_oserror;
	struct addrinfo *ai = NULL, *tmp = NULL;
	struct addrinfo hints = { 0 };
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = 0;
	hs_address_type_to_os_af(in_opt_want_address_type, &hints.ai_family);
	hs_protocol_to_os_protocol(in_opt_want_protocol, &hints.ai_protocol);
	int gair = getaddrinfo(in_opt_addr_string, in_opt_port_string, &hints, &ai);
	if (gair == 0 && ai != NULL) {
		for (tmp = ai; tmp != NULL; tmp = tmp->ai_next) {
			hsr = hs_os_address_to_address(tmp->ai_addr, (socklen_t)tmp->ai_addrlen, out_address_ptr);
			if (hsr == hs_result_ok) {
				break;
			}
		}
	}
	if (ai != NULL) {
		freeaddrinfo(ai);
		ai = NULL;
	}
	return hsr;
}

hs_result hs_socket_poll(
	hs_poll_data inout_poll_data[/*in_length_of_poll_data*/],
	size_t in_length_of_poll_data,
	int in_timeout_in_ms
) {
	if (!initialized)
		return hs_result_notinit;
	/* nothing to do */
	if (!in_length_of_poll_data)
		return hs_result_ok;
	/* can't have a length >1 but null pointer */
	if (!inout_poll_data)
		return hs_result_invarg;
	size_t allocsize = in_length_of_poll_data * sizeof(struct pollfd);
	/* potential overflow occurred? */
	if (allocsize <= in_length_of_poll_data)
		return hs_result_invarg;
	struct pollfd *wsapolldata = (struct pollfd*)alloca(allocsize);
	if (!wsapolldata)
		return hs_result_oserror;
	hs_result r = hs_result_ok;
	for (size_t idx = 0; idx < in_length_of_poll_data; ++idx) {
		if (inout_poll_data[idx].in_socket != hs_invalid_hsocket)
			wsapolldata[idx].fd = fromhsock(inout_poll_data[idx].in_socket);
		else
			wsapolldata[idx].fd = -1;
		r = hs_event_to_os_event(inout_poll_data[idx].inout_events, &wsapolldata[idx].events);
		if (r != hs_result_ok)
			return r;
		wsapolldata[idx].revents = 0;
	}
	int wsar = poll(wsapolldata, (nfds_t)in_length_of_poll_data, in_timeout_in_ms);
	int wsaerr = errno;
	if (wsar < 0) {
		/* timeoutted? network failure? */
		return hs_result_oserror;
	}
	else if (wsar == 0) {
		/* no sockets were triggered, do nothing and reset events... */
		for (size_t idx = 0; idx < in_length_of_poll_data; ++idx) {
			inout_poll_data[idx].inout_events = hs_event_unknown;
		}
		return hs_result_ok;
	}
	/* at least one socket got triggered... */
	for (size_t idx = 0; idx < in_length_of_poll_data; ++idx) {
		r = hs_os_event_to_event(wsapolldata[idx].revents, &inout_poll_data[idx].inout_events);
		if (r != hs_result_ok)
			return r;
	}
	return hs_result_ok;
}

/* yes */
hs_result hs_htons(
	uint16_t* inout_value
) {
	if (!initialized)
		return hs_result_notinit;
	if (!inout_value)
		return hs_result_invarg;
	*inout_value = htons(*inout_value);
	return hs_result_ok;
}

/* yes */
hs_result hs_htonl(
	uint32_t* inout_value
) {
	if (!initialized)
		return hs_result_notinit;
	if (!inout_value)
		return hs_result_invarg;
	*inout_value = htonl(*inout_value);
	return hs_result_ok;
}
