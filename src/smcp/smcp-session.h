/*!	@file smcp-session.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Session tracking
**
**	Copyright (C) 2014 Robert Quattlebaum
**
**	Permission is hereby granted, free of charge, to any person
**	obtaining a copy of this software and associated
**	documentation files (the "Software"), to deal in the
**	Software without restriction, including without limitation
**	the rights to use, copy, modify, merge, publish, distribute,
**	sublicense, and/or sell copies of the Software, and to
**	permit persons to whom the Software is furnished to do so,
**	subject to the following conditions:
**
**	The above copyright notice and this permission notice shall
**	be included in all copies or substantial portions of the
**	Software.
**
**	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
**	KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
**	WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
**	PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
**	OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
**	OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
**	OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
**	SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef SMCP_smcp_session_h
#define SMCP_smcp_session_h

#include "smcp.h"
#include "ll.h"

__BEGIN_DECLS

typedef enum {
	SMCP_SESSION_TYPE_NIL,
	SMCP_SESSION_TYPE_UDP,
	SMCP_SESSION_TYPE_TCP,
	SMCP_SESSION_TYPE_DTLS,
	SMCP_SESSION_TYPE_TLS
} smcp_session_type_t;

typedef enum {
	SMCP_SESSION_STATE_NIL,
	SMCP_SESSION_STATE_CLOSED,
	SMCP_SESSION_STATE_ERROR,
	SMCP_SESSION_STATE_PENDING,
	SMCP_SESSION_STATE_READY
} smcp_session_state_t;

struct smcp_session_s;
typedef struct smcp_session_s* smcp_session_t;

// This structure may one day be entirely opaque
struct smcp_session_s {
//#if SMCP_CONF_MAX_SESSION_COUNT > 1
//#if SMCP_TRANSACTIONS_USE_BTREE
	struct bt_item_s			bt_item;
//#else
	struct ll_item_s			ll_item;
//#endif
	int refcount;
	smcp_session_type_t type;
	smcp_session_state_t state;
	void* context;
//#endif
	smcp_sockaddr_t sockaddr_remote;
	smcp_sockaddr_t sockaddr_local;
};

//////////////////////////////////////////////////////////////////////////
// The following functions are definately public

SMCP_API_EXTERN smcp_session_t smcp_lookup_session(
	smcp_t smcp,
	smcp_session_type_t type,
	const smcp_sockaddr_t* remote,
	const smcp_sockaddr_t* local,
	int flags
);

SMCP_API_EXTERN smcp_session_type_t smcp_session_get_type(smcp_session_t session);

SMCP_API_EXTERN smcp_session_state_t smcp_session_get_state(smcp_session_t session);

SMCP_API_EXTERN void* smcp_session_get_context(smcp_session_t session);

SMCP_API_EXTERN smcp_session_t smcp_get_current_session();

SMCP_API_EXTERN bool smcp_session_type_supports_multicast(smcp_session_type_t session_type);

SMCP_API_EXTERN bool smcp_session_type_is_reliable(smcp_session_type_t session_type);

//////////////////////////////////////////////////////////////////////////
// The following functions MAY end up being public, but I'm not sure.

smcp_session_t smcp_session_retain(smcp_session_t session);

void smcp_session_release(smcp_session_t session);

bool smcp_session_is_local(smcp_session_t session);

smcp_status_t smcp_session_get_error(smcp_session_t session);

void smcp_session_clear_error(smcp_session_t session);

//////////////////////////////////////////////////////////////////////////
// The following functions are going to be PRIVATE

smcp_status_t smcp_collect_sessions(smcp_t smcp);

smcp_status_t smcp_session_send(smcp_session_t session, const uint8_t* data, coap_size_t len, int flags);

__END_DECLS

#endif
