#pragma once
#ifndef _HANSOCK_H_
#define _HANSOCK_H_ 1
/* This is the header for a cross-platform
 * lightweight and tiny C socket API
 * 
 * hansock header begin --
 */

/* I'm pretty sure your system has these headers already... */
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Generic return values for all hansock functions */
typedef enum hs_result {
	/* all is well */
	hs_result_ok,
	/* forgor :skull: to call hs_init() */
	hs_result_notinit,
	/* hs_init() was already called */
	hs_result_already,
	/* socket call returned an error */
	hs_result_oserror,
	/* invalid (NULL or out of range) argument */
	hs_result_invarg,
	/* socket call returned a WOULDBLOCK error */
	hs_result_pending
} hs_result;

typedef enum hs_af {
	hs_af_unknown,
	/* IPv4 */
	hs_af_inet,
	/* IPv6 */
	hs_af_inet6
} hs_af;

typedef enum hs_type {
	hs_type_unknown,
	/* STREAM socket */
	hs_type_stream,
	/* DATAGRAM socket */
	hs_type_dgram
} hs_type;

typedef enum hs_protocol {
	hs_protocol_unknown,
	/* Try to guess based on hs_type */
	hs_protocol_auto = hs_protocol_unknown,
	/* Transmission Control Protocol */
	hs_protocol_tcp,
	/* User Datagram Protocol */
	hs_protocol_udp
} hs_protocol;

typedef enum hs_address_type {
	hs_address_type_unknown,
	/* IPv4 */
	hs_address_type_ipv4,
	/* IPv6 */
	hs_address_type_ipv6
} hs_address_type;

typedef enum hs_feature {
	hs_feature_unknown,
	/* Do not block on accept, read and recv. Return hs_result_pending instead */
	hs_feature_nonblocking,
	/* Allow binding multiple sockets on the same address */
	hs_feature_reuseaddr,
	hs_feature_keepalive
} hs_feature;

typedef enum hs_address_init {
	hs_address_init_unknown,
	/* 0.0.0.0 */
	hs_address_init_ipv4_any,
	/* 127.0.0.1 */
	hs_address_init_ipv4_loopback,
	hs_address_init_ipv4_broadcast,
	/* ::/0 */
	hs_address_init_ipv6_any,
	/* ::1 */
	hs_address_init_ipv6_loopback
} hs_address_init;

/* Always stored in NETWORK BYTE ORDER! */
typedef struct hs_address {
	uint8_t type; /* < enum hs_address_type */
	uint16_t port; /* must be in [1;65534] range */
	union {
		uint32_t ipv4u32; /* NETWORK BYTE ORDER! */
		uint8_t ipv4u8[sizeof(uint32_t)]; /* raw bytes */
		uint8_t ipv6u8[16]; /* raw bytes */
	} addr;
} hs_address, *hs_paddress;

/* (hs_hsocket)SOCKET on Windows, ((hs_hsocket)(intptr_t)int) on Linux */
typedef struct hs_socket hs_socket, *hs_hsocket;

/* which events to poll for in a poll call? */
typedef enum hs_event {
	hs_event_unknown = (0 << 0),
	/* Incoming data or a connection */
	hs_event_in = (1 << 0),
	/* Data can be written without blocking */
	hs_event_out = (1 << 1),
	/* Priority or out of band data */
	hs_event_pri = (1 << 2),
	/* Error condition (return only) */
	hs_event_err = (1 << 3),
	hs_event_hup = (1 << 4),
	/* Invalid socket handle (return only) */
	hs_event_nval = (1 << 5)
} hs_event;

typedef struct hs_poll_data {
	hs_hsocket in_socket;
	/* Bitmask of hs_event values */
	hs_event inout_events;
} hs_poll_data;

/* Invalid socket handle */
#define hs_invalid_hsocket ((hs_hsocket)0)

/* Must be called exactly once before using hansock */
hs_result hs_init(
	void
);

/* Shuts down socket support, make sure ALL sockets are closed before calling this! */
hs_result hs_quit(
	void
);

/* Convert result to human readable string */
static inline hs_result hs_result_to_string(
	hs_result in_result,
	const char** out_string
) {
	*out_string = NULL;
	switch (in_result) {
	case hs_result_ok:
		*out_string = "hs_result_ok: All is well. There is no error."; return hs_result_ok;
	case hs_result_notinit:
		*out_string = "hs_result_notinit: Not initialized. Did you call hs_init?"; return hs_result_ok;
	case hs_result_already:
		*out_string = "hs_result_already: Already happened or occurred."; return hs_result_ok;
	case hs_result_oserror:
		*out_string = "hs_result_oserror: Underlying OS call returned an error code."; return hs_result_ok;
	case hs_result_invarg:
		*out_string = "hs_result_invarg: Invalid (NULL, out of range, etc) argument was passed."; return hs_result_ok;
	case hs_result_pending:
		*out_string = "hs_result_pending: Call is successful but the operation is pending."; return hs_result_ok;
	}
	return hs_result_invarg;
}

/* Helper function to create pre-defined addresses */
hs_result hs_address_create(
	hs_address_init in_address_init,
	uint16_t in_port,
	hs_address* out_address_ptr
);

/* Helper function to create raw IPv4 addresses */
hs_result hs_address_create_from_ipv4(
	uint32_t in_address,
	uint16_t in_port,
	hs_address* out_address_ptr
);

/* getaddrdinfo() wrapper */
hs_result hs_address_create_from_string(
	const char* in_opt_addr_string,
	const char* in_opt_port_string,
	hs_address_type in_opt_want_address_type,
	hs_protocol in_opt_want_protocol,
	hs_address* out_address_ptr
);

/* Turn address to a human readable string */
hs_result hs_address_to_string(
	char *out_string,
	size_t in_size_of_string,
	const hs_address* in_address_ptr
);

/* Creates a socket */
hs_result hs_socket_create(
	hs_af in_address_family,
	hs_type in_socket_type,
	hs_protocol in_socket_protocol,
	hs_hsocket *out_socket_handle
);

/* Binds a socket to a specified address */
hs_result hs_socket_bind(
	const hs_address *in_address_ptr,
	hs_hsocket in_socket
);

/* Binds a socket to a specified address */
hs_result hs_socket_listen(
	int in_backlog,
	hs_hsocket in_socket
);

/* Sends data */
hs_result hs_socket_send(
	const uint8_t in_data[/*in_size_of_data*/],
	size_t in_size_of_data,
	size_t* out_size_of_sent,
	/* for UDP only */ const hs_address* in_opt_address,
	hs_hsocket in_socket
);

/* Gets data up to specified size if possible */
hs_result hs_socket_receive(
	uint8_t out_data[/*in_size_of_data*/],
	size_t in_size_of_data,
	size_t* out_size_of_received,
	/* for UDP only */ hs_address* out_opt_address,
	hs_hsocket in_socket
);

/* Accept a new client if this socket is in listen */
hs_result hs_socket_accept(
	hs_address *out_new_address,
	hs_hsocket *out_new_socket,
	hs_hsocket in_socket
);

/* Connect to target */
hs_result hs_socket_connect(
	const hs_address* in_address,
	hs_hsocket in_socket
);

/* Enable a socket feature, usually must be done right after creation */
hs_result hs_socket_feature(
	hs_feature in_feature_type,
	int in_enable,
	hs_hsocket in_socket
);

/* Closes and shuts down a socket, calls shutdown() and close() for your convenience */
hs_result hs_socket_close(
	hs_hsocket in_socket
);

/* Performs an asynchronous poll */
hs_result hs_socket_poll(
	hs_poll_data inout_poll_data[/*in_length_of_poll_data*/],
	size_t in_length_of_poll_data,
	int in_timeout_in_ms
);

/* Converts the 16 bit value in-place */
hs_result hs_htons(
	uint16_t *inout_value
);

/* Converts the 32 bit value in-place */
hs_result hs_htonl(
	uint32_t* inout_value
);

#ifdef __cplusplus
}
#endif

#endif /* _HANSOCK_H_ */
