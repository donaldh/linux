/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_NETDEV_HW_H
#define _LINUX_NETDEV_HW_H

#include <linux/netdevice.h>

struct net_device_hw_ops {
	void (*offload)(struct net_device *dev,
			struct flow_cls_offload *off);
	char name[16];
};

#endif /* _LINUX_NETDEV_HW_H */
