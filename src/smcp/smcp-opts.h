/*	@file smcp-opts.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2011,2012 Robert Quattlebaum
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

#ifndef SMCP_smcp_opts_h
#define SMCP_smcp_opts_h

/*****************************************************************************/
#pragma mark - SMCP Build Parameters

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef SMCP_EMBEDDED
#define SMCP_EMBEDDED		defined(CONTIKI)
#endif

#ifndef SMCP_USE_BSD_SOCKETS
#define SMCP_USE_BSD_SOCKETS    !SMCP_EMBEDDED
#endif

#ifndef SMCP_DEFAULT_PORT
#define SMCP_DEFAULT_PORT           5683
#endif

#define SMCP_DEFAULT_PORT_CSTR      #SMCP_DEFAULT_PORT

#ifndef SMCP_IPV6_MULTICAST_ADDRESS
#define SMCP_IPV6_MULTICAST_ADDRESS "FF02::5343:4D50"
#endif

#ifndef IPv4_COMPATIBLE_IPv6_PREFIX
#define IPv4_COMPATIBLE_IPv6_PREFIX "::FFFF:"
#endif

#ifndef SMCP_MAX_PATH_LENGTH
#define SMCP_MAX_PATH_LENGTH        (127)
#endif

#ifndef SMCP_MAX_URI_LENGTH
#define SMCP_MAX_URI_LENGTH (SMCP_MAX_PATH_LENGTH + 7 + 6 + 8 * 4 + 7 + 2)
#endif

#if !defined(SMCP_MAX_PACKET_LENGTH) && !defined(SMCP_MAX_CONTENT_LENGTH)
#if CONTIKI
#define SMCP_MAX_PACKET_LENGTH ((UIP_BUFSIZE - UIP_LLH_LEN - UIP_IPUDPH_LEN))
#else
#define SMCP_MAX_CONTENT_LENGTH     (1024)
#endif
#endif

#if defined(SMCP_MAX_PACKET_LENGTH) && !defined(SMCP_MAX_CONTENT_LENGTH)
#define SMCP_MAX_CONTENT_LENGTH     (SMCP_MAX_PACKET_LENGTH-128)
#endif

#if !defined(SMCP_MAX_PACKET_LENGTH) && defined(SMCP_MAX_CONTENT_LENGTH)
#define SMCP_MAX_PACKET_LENGTH      ((size_t)SMCP_MAX_CONTENT_LENGTH+128)
#endif

#ifndef SMCP_USE_CASCADE_COUNT
#define SMCP_USE_CASCADE_COUNT      (0)
#endif

#ifndef SMCP_MAX_CASCADE_COUNT
#define SMCP_MAX_CASCADE_COUNT      (128)
#endif

#ifndef SMCP_ADD_NEWLINES_TO_LIST_OUTPUT
#define SMCP_ADD_NEWLINES_TO_LIST_OUTPUT	0
#endif

#ifndef SMCP_AVOID_PRINTF
#define SMCP_AVOID_PRINTF	SMCP_EMBEDDED
#endif

#ifndef SMCP_CONF_USE_DNS
#define SMCP_CONF_USE_DNS		1
#endif

/*****************************************************************************/
#pragma mark - Timer Node Options

#ifndef SMCP_CONF_TIMER_NODE_INCLUDE_COUNT
#define SMCP_CONF_TIMER_NODE_INCLUDE_COUNT !defined(__SDCC)
#endif

/*****************************************************************************/
#pragma mark - Pairing/Observation Options

#ifndef SMCP_ENABLE_PAIRING
#define SMCP_ENABLE_PAIRING	!defined(__SDCC)
#endif

#ifndef SMCP_CONF_PAIRING_STATS
#define SMCP_CONF_PAIRING_STATS SMCP_EMBEDDED
#endif

#ifndef SMCP_CONF_USE_SEQ
#define SMCP_CONF_USE_SEQ SMCP_EMBEDDED
#endif

#ifndef SMCP_PAIRING_DEFAULT_ROOT_PATH
#define SMCP_PAIRING_DEFAULT_ROOT_PATH	".p"
#endif

/*****************************************************************************/
#pragma mark - SMCP Compiler Stuff

#if SMCP_EMBEDDED
#define SMCP_NON_RECURSIVE	static
#else
#define SMCP_NON_RECURSIVE
#endif

#ifndef SMCP_DEPRECATED
#if __GCC_VERSION__
#define SMCP_DEPRECATED
#else
#define SMCP_DEPRECATED __attribute__ ((deprecated))
#endif
#endif

#endif