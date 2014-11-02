/*	@file smcp-plat-bsd.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
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

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef DEBUG
#define DEBUG VERBOSE_DEBUG
#endif

#include "assert-macros.h"

#include "smcp.h"

#if SMCP_USE_BSD_SOCKETS

#include "smcp-internal.h"
#include "smcp-logging.h"

#include <stdio.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>

#ifndef SOCKADDR_HAS_LENGTH_FIELD
#if defined(__KAME__)
#define SOCKADDR_HAS_LENGTH_FIELD 1
#endif
#endif

smcp_t
smcp_init(
	smcp_t self, uint16_t port
) {
#if SMCP_EMBEDDED
	smcp_t self = smcp_get_current_instance();
#endif

	require(self != NULL, bail);

	if(port == 0)
		port = COAP_DEFAULT_PORT;

	smcp_sockaddr_t saddr = {
#if SOCKADDR_HAS_LENGTH_FIELD
		.___smcp_len		= sizeof(smcp_sockaddr_t),
#endif
		.___smcp_family	= SMCP_BSD_SOCKETS_NET_FAMILY,
		.smcp_port		= htons(port),
	};

	// Clear the entire structure.
	memset(self, 0, sizeof(*self));

	// Set up the UDP port for listening.
	uint16_t attempts = 0x7FFF;

	self->mcfd = -1;
	self->fd = -1;
	errno = 0;

	self->fd = socket(SMCP_BSD_SOCKETS_NET_FAMILY, SOCK_DGRAM, IPPROTO_UDP);
	int prev_errno = errno;

	require_action_string(
		self->fd >= 0,
		bail, (
			smcp_release(self),
			self = NULL
		),
		strerror(prev_errno)
	);

#if defined(IPV6_V6ONLY) && SMCP_BSD_SOCKETS_NET_FAMILY==AF_INET6
	{
		int value = 0; /* explicitly allow ipv4 traffic too (required on bsd and some debian installations) */
		if (setsockopt(self->fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)) < 0)
		{
			DEBUG_PRINTF(CSTR("Socket won't allow IPv4 connections"));
		}
	}
#endif

	// Keep attempting to bind until we find a port that works.
	while(bind(self->fd, (struct sockaddr*)&saddr, sizeof(saddr)) != 0) {
		// We should only continue trying if errno == EADDRINUSE.
		require_action_string(errno == EADDRINUSE, bail,
			{ DEBUG_PRINTF(CSTR("errno=%d"), errno); smcp_release(
				    self); self = NULL; }, "Failed to bind socket");
		port++;

		// Make sure we aren't in an infinite loop.
		require_action_string(--attempts, bail,
			{ DEBUG_PRINTF(CSTR("errno=%d"), errno); smcp_release(
				    self); self = NULL; }, "Failed to bind socket (ran out of ports)");

		saddr.smcp_port = htons(port);
	}


	{	// Handle sockopts.
		int value;

#ifdef SMCP_RECVPKTINFO
		value = 1;
		setsockopt(self->fd, SMCP_IPPROTO, SMCP_RECVPKTINFO, &value, sizeof(value));
#endif
	}


#if SMCP_BSD_SOCKETS_NET_FAMILY==AF_INET6
	// Go ahead and start listening on our multicast address as well.
	{   // Join the multicast group for COAP_MULTICAST_IP6_LL_ALLDEVICES
		struct ipv6_mreq imreq;
		int btrue = 1;
		struct hostent *tmp = gethostbyname2(COAP_MULTICAST_IP6_LL_ALLDEVICES,
			AF_INET6);
		memset(&imreq, 0, sizeof(imreq));
		self->mcfd = socket(SMCP_BSD_SOCKETS_NET_FAMILY, SOCK_DGRAM, 0);

		require(!h_errno && tmp, skip_mcast);
		require(tmp->h_length > 1, skip_mcast);

		memcpy(&imreq.ipv6mr_multiaddr.s6_addr, tmp->h_addr_list[0], 16);

		require(0 ==
			setsockopt(self->mcfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
				&btrue,
				sizeof(btrue)), skip_mcast);

		// Do a precautionary leave group, to clear any stake kernel data.
		setsockopt(self->mcfd,
			IPPROTO_IPV6,
			IPV6_LEAVE_GROUP,
			&imreq,
			sizeof(imreq));

		require_quiet(0 ==
			setsockopt(self->mcfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &imreq,
				sizeof(imreq)), skip_mcast);

	skip_mcast:
		(void)0;
	}
#else
#warning TODO: Implement joining the multicast group for this network family!
#endif

bail:
	return self;
}

void
smcp_release_plat(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;

	if(self->fd>=0)
		close(self->fd);
	if(self->mcfd>=0)
		close(self->mcfd);
}

int
smcp_get_fd(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;
	return self->fd;
}

uint16_t
smcp_get_port(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;
	smcp_sockaddr_t saddr;
	socklen_t socklen = sizeof(saddr);
	getsockname(self->fd, (struct sockaddr*)&saddr, &socklen);
	return ntohs(saddr.smcp_port);
}

int
smcp_plat_update_pollfds(
	smcp_t self,
    struct pollfd fds[],
	int maxfds
) {
	int ret = 1;

	require_quiet(maxfds > 0, bail);

	assert(fds != NULL);

	fds->fd = self->fd;
	fds->events = POLLIN | POLLHUP;
	fds->revents = 0;
	fds++;
	maxfds--;

bail:
	return ret;
}


static ssize_t
sendtofrom(
	int fd,
	const void *data, size_t len, int flags,
	const struct sockaddr * saddr_to, socklen_t socklen_to,
	const struct sockaddr * saddr_from, socklen_t socklen_from
)
{
	ssize_t ret = -1;
	if ((socklen_from == 0) || (saddr_from->sa_family != saddr_to->sa_family)) {
		ret = sendto(
			fd,
			data,
			len,
			0,
			(struct sockaddr *)&saddr_to,
			socklen_to
		);
	} else {
		struct iovec iov = { (void *)data, len };
		uint8_t cmbuf[CMSG_SPACE(sizeof (struct in6_pktinfo))];
		struct cmsghdr *scmsgp;
		struct msghdr msg = {
			.msg_name = &saddr_to,
			.msg_namelen = socklen_to,
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cmbuf,
			.msg_controllen = sizeof(cmbuf),
		};

#if defined(AF_INET6)
		if (saddr_to->sa_family == AF_INET6) {
			struct in6_pktinfo *pktinfo;
			scmsgp = CMSG_FIRSTHDR(&msg);
			scmsgp->cmsg_level = IPPROTO_IPV6;
			scmsgp->cmsg_type = IPV6_PKTINFO;
			scmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
			pktinfo = (struct in6_pktinfo *)(CMSG_DATA(scmsgp));

			pktinfo->ipi6_addr = ((struct sockaddr_in6*)saddr_from)->sin6_addr;
			pktinfo->ipi6_ifindex = ((struct sockaddr_in6*)saddr_from)->sin6_scope_id;
		} else
#endif

		if (saddr_to->sa_family == AF_INET) {
			struct in_pktinfo *pktinfo;
			scmsgp = CMSG_FIRSTHDR(&msg);
			scmsgp->cmsg_level = IPPROTO_IPV4;
			scmsgp->cmsg_type = IP_PKTINFO;
			scmsgp->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
			pktinfo = (struct in_pktinfo *)(CMSG_DATA(scmsgp));

			pktinfo->ipi_spec_dst = ((struct sockaddr_in*)saddr_from)->sin_addr;
			pktinfo->ipi_addr = ((struct sockaddr_in*)saddr_to)->sin_addr;
			pktinfo->ipi_ifindex = 0;
		}

		ret = sendmsg(fd, &msg, flags);
	}

	return ret;
}


smcp_status_t
smcp_plat_session_send_udp(smcp_session_t session, const uint8_t* data, coap_size_t len, int flags)
{
	assert(session->type == SMCP_SESSION_TYPE_UDP);

	smcp_status_t ret = SMCP_STATUS_FAILURE;
	const int fd = (int)(intptr_t)session->context;
	ssize_t sent_bytes = -1;

	assert(fd >= 0);

	errno = EDESTADDRREQ;

	//sent_bytes = send(fd, data, len, flags);

	if ((sent_bytes == -1) && ((errno == EDESTADDRREQ) || (errno == EINVAL))) {
		sent_bytes = sendtofrom(
			fd,
			data,
			len,
			0,
			(struct sockaddr *)&session->sockaddr_remote,
			sizeof(&session->sockaddr_remote),
			(struct sockaddr *)&session->sockaddr_local,
			sizeof(&session->sockaddr_local)
		);
	}

	require_action_string(
		(sent_bytes >= 0),
		bail, ret = SMCP_STATUS_ERRNO, strerror(errno)
	);

	require_action_string(
		(sent_bytes != 0),
		bail, ret = SMCP_STATUS_FAILURE, "sendto() returned zero."
	);

	ret = SMCP_STATUS_OK;
bail:
	return ret;
}

// MARK: -

smcp_status_t
smcp_wait(
	smcp_t self, cms_t cms
) {
	SMCP_EMBEDDED_SELF_HOOK;
	smcp_status_t ret = 0;
	struct pollfd pollee = { self->fd, POLLIN | POLLHUP, 0 };

	if(cms >= 0)
		cms = MIN(cms, smcp_get_timeout(self));
	else
		cms = smcp_get_timeout(self);

	errno = 0;

	if (poll(&pollee, 1, cms) == 0) {
		ret = SMCP_STATUS_TIMEOUT;
	}

	// Ensure that poll did not fail with an error.
	require_action_string(errno == 0,
		bail,
		ret = SMCP_STATUS_ERRNO,
		strerror(errno)
	);

bail:
	return ret;
}

smcp_status_t
smcp_process(
	smcp_t self
) {
	SMCP_EMBEDDED_SELF_HOOK;
	smcp_status_t ret = 0;

	int tmp;
	struct pollfd pollee = { self->fd, POLLIN | POLLHUP, 0 };

	errno = 0;

	tmp = poll(&pollee, 1, 0);

	// Ensure that poll did not fail with an error.
	require_action_string(errno == 0,
		bail,
		ret = SMCP_STATUS_ERRNO,
		strerror(errno)
	);

	if(tmp > 0) {
		char packet[SMCP_MAX_PACKET_LENGTH+1];
		smcp_sockaddr_t packet_saddr;
		ssize_t packet_len = 0;
		char cmbuf[0x100];
		struct iovec iov = { packet, SMCP_MAX_PACKET_LENGTH };
		struct msghdr msg = {
			.msg_name = &packet_saddr,
			.msg_namelen = sizeof(packet_saddr),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cmbuf,
			.msg_controllen = sizeof(cmbuf),
		};
		struct cmsghdr *cmsg;
		smcp_sockaddr_t* src_addr = NULL;
		smcp_sockaddr_t* dst_addr = NULL;

		packet_len = recvmsg(self->fd, &msg, 0);

		require_action(packet_len > 0, bail, ret = SMCP_STATUS_ERRNO);

		packet[packet_len] = 0;

		ret = smcp_inbound_start_packet(self, msg.msg_iov[0].iov_base, (coap_size_t)packet_len);
		require(ret==SMCP_STATUS_OK,bail);

		// Set the source address
		src_addr = (smcp_sockaddr_t*)msg.msg_name;

		for (
			cmsg = CMSG_FIRSTHDR(&msg);
			cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msg, cmsg)
		) {
			if (cmsg->cmsg_level != SMCP_IPPROTO
				|| cmsg->cmsg_type != SMCP_PKTINFO
			) {
				continue;
			}

#if SMCP_BSD_SOCKETS_NET_FAMILY==AF_INET6
			struct in6_pktinfo *pi = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			packet_saddr.smcp_addr = pi->ipi6_addr;
			packet_saddr.sin6_scope_id = pi->ipi6_ifindex;
#elif SMCP_BSD_SOCKETS_NET_FAMILY==AF_INET
			struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
			packet_saddr.smcp_addr = pi->ipi_addr;
#endif
			packet_saddr.smcp_port = htons(smcp_get_port(self));
			dst_addr = (smcp_sockaddr_t*)&packet_saddr;

			self->inbound.pktinfo = *pi;
		}

		self->current_session = smcp_lookup_session(
			self,
			SMCP_SESSION_TYPE_UDP,
			src_addr,
			dst_addr,
			0
		);
		require(ret==SMCP_STATUS_OK,bail);

		ret = smcp_inbound_finish_packet();
		require(ret==SMCP_STATUS_OK,bail);
	}

	smcp_set_current_instance(self);
	smcp_handle_timers(self);

bail:
	smcp_set_current_instance(NULL);
	self->is_responding = false;
	return ret;
}

smcp_status_t
smcp_internal_lookup_hostname(const char* hostname, smcp_sockaddr_t* saddr)
{
	smcp_status_t ret;
	struct addrinfo hint = {
		.ai_flags		= AI_ADDRCONFIG,
		.ai_family		= AF_UNSPEC,
	};

	struct addrinfo *results = NULL;
	struct addrinfo *iter = NULL;

	memset(saddr, 0, sizeof(*saddr));
	saddr->___smcp_family = SMCP_BSD_SOCKETS_NET_FAMILY;

#if SOCKADDR_HAS_LENGTH_FIELD
	saddr->___smcp_len = sizeof(*saddr);
#endif

	int error = getaddrinfo(hostname, NULL, &hint, &results);

#if SMCP_BSD_SOCKETS_NET_FAMILY==AF_INET6
	if(error && (inet_addr(hostname) != INADDR_NONE)) {
		char addr_v4mapped_str[8 + strlen(hostname)];
		hint.ai_family = AF_INET6;
		hint.ai_flags = AI_ALL | AI_V4MAPPED,
		strcpy(addr_v4mapped_str,"::ffff:");
		strcat(addr_v4mapped_str,hostname);
		error = getaddrinfo(addr_v4mapped_str,
			NULL,
			&hint,
			&results
		);
	}
#endif

	if (EAI_AGAIN == error) {
		ret = SMCP_STATUS_WAIT_FOR_DNS;
		goto bail;
	}

#ifdef TM_EWOULDBLOCK
	if (TM_EWOULDBLOCK == error) {
		ret = SMCP_STATUS_WAIT_FOR_DNS;
		goto bail;
	}
#endif

	require_action_string(
		!error,
		bail,
		ret = SMCP_STATUS_HOST_LOOKUP_FAILURE,
		gai_strerror(error)
	);

	// Move to the first recognized result
	for(iter = results;iter && (iter->ai_family!=AF_INET6 && iter->ai_family!=AF_INET);iter=iter->ai_next);

	require_action(
		iter,
		bail,
		ret = SMCP_STATUS_HOST_LOOKUP_FAILURE
	);

#if SMCP_BSD_SOCKETS_NET_FAMILY==AF_INET6
	if(iter->ai_family == AF_INET) {
		struct sockaddr_in *v4addr = (void*)iter->ai_addr;
		saddr->sin6_addr.s6_addr[10] = 0xFF;
		saddr->sin6_addr.s6_addr[11] = 0xFF;
		memcpy(&saddr->sin6_addr.s6_addr[12], &v4addr->sin_addr.s_addr, 4);
	} else
#endif
	if(iter->ai_family == SMCP_BSD_SOCKETS_NET_FAMILY) {
		memcpy(saddr, iter->ai_addr, iter->ai_addrlen);
	}

	if(SMCP_IS_ADDR_MULTICAST(&saddr->smcp_addr)) {
		smcp_t const self = smcp_get_current_instance();
		check(self->outbound.packet->tt != COAP_TRANS_TYPE_CONFIRMABLE);
		if(self->outbound.packet->tt == COAP_TRANS_TYPE_CONFIRMABLE) {
			self->outbound.packet->tt = COAP_TRANS_TYPE_NONCONFIRMABLE;
		}
	}

	ret = SMCP_STATUS_OK;

bail:
	if(results)
		freeaddrinfo(results);
	return ret;
}










#endif // #if SMCP_USE_BSD_SOCKETS
