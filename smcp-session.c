/*!	@file smcp-session.c
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#define SMCP_CONF_MAX_SESSION_COUNT		10
#define SMCP_AVOID_MALLOC	1

//#define ASSERT_MACROS_USE_VANILLA_PRINTF 1
//#define SMCP_DEBUG_TIMERS	1
//#define VERBOSE_DEBUG 1
//#define DEBUG 1

#include "assert-macros.h"
#include "smcp.h"
#include "smcp-internal.h"

#if !SMCP_DEBUG_TIMERS && !VERBOSE_DEBUG
#undef DEBUG_PRINTF
#define DEBUG_PRINTF(fmt, ...) do { } while(0)
#endif

#include <stdio.h>

#if SMCP_SESSIONS_USE_BTREE
static bt_compare_result_t
smcp_session_compare(
	const void* lhs_, const void* rhs_, void* context
) {
	const smcp_session_t lhs = (smcp_session_t)lhs_;
	const smcp_session_t rhs = (smcp_session_t)rhs_;

	if (lhs == rhs) {
		return true;
	}

	{
		bt_compare_result_t ret = 0;
		ret = memcmp(&lhs->sockaddr_remote, &rhs->sockaddr_remote, sizeof(lhs->sockaddr_remote));
		if (ret != 0) {
			return ret;
		}
	}

	if (lhs->type > rhs->type) {
		return 1;
	}

	if (lhs->type < rhs->type) {
		return -1;
	}

	{
		bt_compare_result_t ret = 0;
		ret = memcmp(&lhs->sockaddr_local, &rhs->sockaddr_local, sizeof(lhs->sockaddr_local));
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

struct session_compare_arguments_s {
	const smcp_sockaddr_t* remote;
	const smcp_sockaddr_t* local;
	smcp_session_type_t type;
};

static bt_compare_result_t
smcp_session_compare_sockaddr(
	const void* lhs_, const void* rhs_, void* context
) {
	const smcp_transaction_t lhs = (smcp_transaction_t)lhs_;
	const struct session_compare_arguments_s *rhs = (const struct session_compare_arguments_s *)rhs_;

	if (rhs->remote != NULL) {
		bt_compare_result_t ret = 0;
		ret = memcmp(&lhs->sockaddr_remote, rhs->remote, sizeof(lhs->sockaddr_remote));
		if (ret != 0) {
			return ret;
		}
	}

	if (rhs->type != SMCP_SESSION_TYPE_NIL) {
		if (lhs->type > rhs->type) {
			return 1;
		}

		if (lhs->type < rhs->type) {
			return -1;
		}
	}

	if (rhs->local != NULL) {
		bt_compare_result_t ret = 0;
		ret = memcmp(&lhs->sockaddr_local, rhs->local, sizeof(lhs->sockaddr_local));
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}
#endif

#if SMCP_CONF_MAX_SESSION_COUNT != 1
smcp_session_t
smcp_get_next_free_session(smcp_t self) {
	smcp_session_t ret;
#if SMCP_AVOID_MALLOC
	int i = SMCP_CONF_MAX_SESSION_COUNT;

	for (i = SMCP_CONF_MAX_SESSION_COUNT,ret = &self->session_table[0];
	     i--;
		 ret++
	) {
		if (ret->type == SMCP_SESSION_TYPE_NIL) {
			memset(ret, 0, sizeof(*ret));
			return ret;
		}
	}
	return NULL;
#else
	ret = calloc(sizeof(*ret),1);
	return ret;
#endif
}
#endif

smcp_status_t
smcp_collect_sessions(smcp_t self)
{
	// TODO: Writeme!
	return SMCP_STATUS_NOT_IMPLEMENTED;
}


smcp_session_t
smcp_lookup_session(
	smcp_t self,
	smcp_session_type_t type,
	const smcp_sockaddr_t* remote,
	const smcp_sockaddr_t* local,
	int flags
) {
	require(remote != NULL, )
#if SMCP_CONF_MAX_SESSION_COUNT == 1
	// Only one session...
	return type == SMCP_SESSION_TYPE_UDP ? &self->default_session : NULL;
#else
	// Multiple session support.
	struct session_compare_arguments_s args = { remote, local, type };
	smcp_session_t ret;

	ret = bt_find(&self->sessions, &args, &smcp_session_compare_sockaddr, NULL);

	if (ret == NULL) {
		// No session found, try making another one.
		ret = smcp_get_next_free_session(self);

		if (ret == NULL) {
			// TODO: Retire one of the sessions already in progress.
			goto bail;
		}

		ret->type = type;
		if (remote != NULL) {
			memcpy(&ret->sockaddr_remote, *remote, sizeof(ret->sockaddr_remote));
		}
	}

	if (ret != NULL) {
		// Splay the tree to optimize it.
		bt_splay(&self->sessions, ret);
	}

bail:
	return ret;
#endif
}

smcp_session_type_t
smcp_session_get_type(smcp_session_t session)
{
	return session->type;
}

smcp_session_state_t
smcp_session_get_state(smcp_session_t session)
{
	return session->state;
}

void*
smcp_session_get_context(smcp_session_t session)
{
	return session->context;
}

smcp_session_t
smcp_get_current_session()
{
	smcp_t const self = smcp_get_current_instance();
#if SMCP_CONF_MAX_SESSION_COUNT == 1
	return &self->default_session;
#else
	return self->current_session;
#endif
}

bool
smcp_session_type_supports_multicast(smcp_session_type_t session_type)
{
	return session_type == SMCP_SESSION_TYPE_UDP;
}

bool
smcp_session_type_is_reliable(smcp_session_type_t session_type)
{
	return (session_type == SMCP_SESSION_TYPE_TCP)
		|| (session_type == SMCP_SESSION_TYPE_TLS);
}

smcp_session_t
smcp_session_retain(smcp_session_t session)
{
#if SMCP_CONF_MAX_SESSION_COUNT > 1
	if (session != NULL) {
		session->refcount++;
	}
#endif
	return session;
}

void
smcp_session_release(smcp_session_t session)
{
#if SMCP_CONF_MAX_SESSION_COUNT > 1
	if (session != NULL) {
		session->refcount--;
	}
#endif
}

smcp_status_t
smcp_session_get_error(smcp_session_t session)
{
	// TODO: Writeme!
	return SMCP_STATUS_OK;
}

void
smcp_session_clear_error(smcp_session_t session)
{
}

smcp_status_t
smcp_session_send(smcp_session_t* session, const uint8_t* data, coap_size_t len, int flags)
{
	// TODO: Writeme!
	return SMCP_STATUS_NOT_IMPLEMENTED;
}
