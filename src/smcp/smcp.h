/*	Simple Monitoring and Control Protocol (SMCP)
**	Stack Implementation
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
**	PUBLIC DOMAIN.
*/


#ifndef __SMCP_HEADER__
#define __SMCP_HEADER__ 1

#if !defined(__BEGIN_DECLS) || !defined(__END_DECLS)
#if defined(__cplusplus)
#define __BEGIN_DECLS   extern "C" {
#define __END_DECLS \
	}
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
//#include <sys/errno.h>

#ifdef __CONTIKI__
#include "contiki.h"
#include "net/uip.h"
#define SMCP_USE_BSD_SOCKETS    0
#endif

#ifdef __APPLE__
#define SMCP_FUNC_RANDOM_UINT32()   arc4random()
#endif

#ifndef SMCP_FUNC_RANDOM_UINT32
#define SMCP_FUNC_RANDOM_UINT32()   random()
#endif

#ifndef SMCP_USE_BSD_SOCKETS
#define SMCP_USE_BSD_SOCKETS    1
#endif

#if SMCP_USE_BSD_SOCKETS
#include <netinet/in.h>
#include <arpa/inet.h>
#define SMCP_SOCKET_ARGS        struct sockaddr* saddr, socklen_t socklen
#endif

#if !SMCP_USE_BSD_SOCKETS && defined(__CONTIKI__)
#define SMCP_SOCKET_ARGS \
    const uip_ipaddr_t *toaddr, \
    uint16_t toport
#include "net/uip.h"
#endif

#ifndef SMCP_DEPRECATED
#if __GCC_VERSION__
#define SMCP_DEPRECATED
#else
#define SMCP_DEPRECATED __attribute__ ((deprecated))
#endif
#endif

#define SMCP_DEFAULT_PORT           (61616)
#define SMCP_DEFAULT_PORT_CSTR      "61616"
#if __CONTIKI__
#define SMCP_MAX_PACKET_LENGTH \
        ((UIP_BUFSIZE - UIP_LLH_LEN - \
            UIP_IPUDPH_LEN))
#else
#define SMCP_MAX_PACKET_LENGTH      ((size_t)1200)
#endif
#define SMCP_MAX_CONTENT_LENGTH     (512)
#define SMCP_MAX_HEADERS            (15)
#define SMCP_IPV6_MULTICAST_ADDRESS "FF02::5343:4D50"
#define SMCP_MAX_PATH_LENGTH        (127)
#define SMCP_MAX_URI_LENGTH \
        (SMCP_MAX_PATH_LENGTH + 7 + 6 + 8 * \
        4 + 7 + 2)

#ifndef IPv4_COMPATIBLE_IPv6_PREFIX
#define IPv4_COMPATIBLE_IPv6_PREFIX "::FFFF:"
#endif

#define SMCP_MAX_CASCADE_COUNT      (128)

#include "coap.h"

__BEGIN_DECLS

#include "btree.h"


typedef int smcp_method_t;


enum {
	SMCP_STATUS_OK                  = 0,
	SMCP_STATUS_FAILURE             = -1,
	SMCP_STATUS_INVALID_ARGUMENT    = -2,
	SMCP_STATUS_BAD_NODE_TYPE       = -3,
	SMCP_STATUS_UNSUPPORTED_URI     = -4,
	SMCP_STATUS_ERRNO               = -5,
	SMCP_STATUS_MALLOC_FAILURE      = -6,
	SMCP_STATUS_HANDLER_INVALIDATED = -7,
	SMCP_STATUS_TIMEOUT             = -8,
	SMCP_STATUS_NOT_IMPLEMENTED     = -9,
	SMCP_STATUS_NOT_FOUND           = -10,
	SMCP_STATUS_H_ERRNO             = -11,
	SMCP_STATUS_RESPONSE_NOT_ALLOWED = -12,
	SMCP_STATUS_BAD_HOSTNAME        = -13,
	SMCP_STATUS_LOOP_DETECTED       = -14,
	SMCP_STATUS_BAD_ARGUMENT        = -15,
};

typedef int smcp_status_t;

extern const char* smcp_status_to_cstr(smcp_status_t x);


// Avoid using the following preprocessor macros. They were used for a transition period which is now over.
#define HEADER_CSTR_LEN     ((size_t)-1)
#define smcp_header_item_next(item)         ((item) + 1)
#define smcp_header_item_get_value(item)    ((item)->value)
#define smcp_header_item_get_key(item)      ((item)->key)
#define smcp_header_item_set_value(item, x)  ((item)->value = (x))
#define smcp_header_item_set_key(item, x)        ((item)->key = (x))
#define smcp_header_item_get_value_len(item)        ((item)->value_len)
#define smcp_header_item_key_equal(item, k)      ((item)->key == (k))
#define smcp_header_item_get_key_cstr(item) \
    coap_header_key_to_cstr( \
	    smcp_header_item_get_key(item))


struct smcp_daemon_s;
typedef struct smcp_daemon_s *smcp_daemon_t;

struct smcp_node_s;
typedef struct smcp_node_s *smcp_node_t;

struct smcp_pairing_s;
typedef struct smcp_pairing_s *smcp_pairing_t;

enum {
	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_MASK
	**	@abstract Bitmask for obtaining the reliability from
	**	          pairing flags.
	*/
	SMCP_PARING_FLAG_RELIABILITY_MASK = (3 << 0),

	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_NONE
	**	@abstract Events are transmitted unreliably.
	*/
	SMCP_PARING_FLAG_RELIABILITY_NONE = (0 << 0),

	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_ASAP
	**	@abstract Events are transmitted reliably out-of-order.
	**	          Order-of-events is maintained per-pairing.
	**	          NOTE: Currently unimplemented!
	*/
	SMCP_PARING_FLAG_RELIABILITY_ASAP = (1 << 0),

	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_PART
	**	@abstract Events transmitted and will be retransmitted
	**	          until either the event is ACKed or the event
	**	          is superceded by a more recent event.
	**	          NOTE: Currently unimplemented!
	*/
	SMCP_PARING_FLAG_RELIABILITY_PART = (2 << 0),

	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_FULL
	**	@abstract Events are transmitted reliably and in-order.
	**	          Order-of-events is maintained per-pairing.
	**	          NOTE: Currently unimplemented!
	*/
	SMCP_PARING_FLAG_RELIABILITY_FULL = (3 << 0),

	/*!	@enum SMCP_PARING_FLAG_TEMPORARY
	**	@abstract Pairing is not to be comitted to
	**	          non-volatile storage.
	*/
	SMCP_PARING_FLAG_TEMPORARY = (1 << 2),
};


enum {
	SMCP_RESPONSE_HANDLER_ALWAYS_TIMEOUT = (1 << 0),
};

typedef int32_t cms_t;

typedef void (*smcp_response_handler_func)(smcp_daemon_t self,
    int statuscode, const char* content, size_t content_length,
    void* context);

extern int smcp_convert_status_to_result_code(smcp_status_t status);


extern smcp_daemon_t smcp_daemon_create(uint16_t port);
extern smcp_daemon_t smcp_daemon_init(
	smcp_daemon_t self, uint16_t port);
extern void smcp_daemon_release(smcp_daemon_t self);

extern uint16_t smcp_daemon_get_port(smcp_daemon_t self);

extern smcp_status_t smcp_daemon_process(
	smcp_daemon_t self, cms_t cms);                                     // Returns nonzero on error
extern cms_t smcp_daemon_get_timeout(smcp_daemon_t self);

extern smcp_node_t smcp_daemon_get_root_node(smcp_daemon_t self);

extern smcp_status_t smcp_daemon_add_response_handler(
	smcp_daemon_t				self,
	coap_transaction_id_t		tid,
	cms_t						cmsExpiration,
	int							flags,
	smcp_response_handler_func	callback,
	void*						context);
extern smcp_status_t smcp_invalidate_response_handler(
	smcp_daemon_t self, coap_transaction_id_t tid);

extern smcp_status_t smcp_daemon_send_request(
	smcp_daemon_t			self,
	coap_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	const char*				query,
	coap_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS);
extern smcp_status_t smcp_daemon_send_request_to_url(
	smcp_daemon_t			self,
	coap_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				url,
	coap_header_item_t		headers[],
	const char*				content,
	size_t					content_length);

extern smcp_status_t smcp_daemon_send_response(
	smcp_daemon_t		self,
	int					statuscode,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length);

#pragma mark -
#pragma mark Network Interface

#if SMCP_USE_BSD_SOCKETS
extern int smcp_daemon_get_fd(smcp_daemon_t self);
#elif defined(__CONTIKI__)
extern struct uip_udp_conn* smcp_daemon_get_udp_conn(smcp_daemon_t self);
#endif

extern smcp_status_t smcp_daemon_handle_inbound_packet(
	smcp_daemon_t	self,
	char*			packet,
	size_t			packet_length,
	SMCP_SOCKET_ARGS);


#pragma mark -
#pragma mark Node Functions

extern smcp_node_t smcp_node_alloc();

extern smcp_node_t smcp_node_init(
	smcp_node_t self, smcp_node_t parent, const char* name);

extern void smcp_node_delete(smcp_node_t node);
extern smcp_status_t smcp_node_get_path(
	smcp_node_t node, char* path, size_t max_path_len);
extern smcp_node_t smcp_node_find_with_path(
	smcp_node_t node, const char* path);
extern int smcp_node_find_closest_with_path(
	smcp_node_t node, const char* path, smcp_node_t* closest);
extern int smcp_node_find_next_with_path(
	smcp_node_t node, const char* path, smcp_node_t* next);

extern smcp_status_t smcp_default_request_handler(
	smcp_daemon_t	self,
	smcp_node_t		node,
	smcp_method_t	method,
	const char*		relative_path,
	const char*		content,
	size_t			content_length);


coap_transaction_id_t smcp_daemon_get_current_tid(smcp_daemon_t self);

#if SMCP_USE_BSD_SOCKETS
extern struct sockaddr* smcp_daemon_get_current_request_saddr(
	smcp_daemon_t self);
extern socklen_t smcp_daemon_get_current_request_socklen(
	smcp_daemon_t self);
#elif defined(__CONTIKI__)
extern const uip_ipaddr_t* smcp_daemon_get_current_request_ipaddr(
	smcp_daemon_t self);
extern const uint16_t smcp_daemon_get_current_request_ipport(
	smcp_daemon_t self);
#endif

extern const coap_header_item_t* smcp_daemon_get_current_request_headers(
	smcp_daemon_t self);
extern uint8_t smcp_daemon_get_current_request_header_count(
	smcp_daemon_t self);

__END_DECLS

#endif

#include "smcp_helpers.h"