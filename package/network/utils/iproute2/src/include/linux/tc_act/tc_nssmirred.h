/*
 **************************************************************************
 * Copyright (c) 2019 The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

#ifndef __LINUX_TC_NSS_MIR_H
#define __LINUX_TC_NSS_MIR_H

#include <linux/types.h>
#include <linux/pkt_cls.h>

/*
 * tc_nss_mirred
 *	Structure for nssmirred action.
 */
struct tc_nss_mirred {
	tc_gen;
	__u32                   from_ifindex;  /* ifindex of the port to be redirected from */
	__u32                   to_ifindex;  /* ifindex of the port to be redirected to */
};

/*
 * Types of nssmirred action parameters.
 */
enum {
	TCA_NSS_MIRRED_UNSPEC,
	TCA_NSS_MIRRED_TM,
	TCA_NSS_MIRRED_PARMS,
	__TCA_NSS_MIRRED_MAX
};
#define TCA_NSS_MIRRED_MAX (__TCA_NSS_MIRRED_MAX - 1)

#endif	/* __LINUX_TC_NSS_MIR_H */
