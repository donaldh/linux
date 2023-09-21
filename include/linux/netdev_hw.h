/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_NETDEV_HW_H
#define _LINUX_NETDEV_HW_H

#include <linux/netdevice.h>
#include <net/flow_offload.h>

struct net_device_hw_ops {
	void (*offload)(struct net_device *dev,
			struct flow_cls_offload *off);
	int (*setup_tc)(struct net_device *dev,
			int type,
			void *type_data);
	int (*setup_ft)(enum tc_setup_type type,
			void *type_data,
			void *cb_priv);
	char name[16];
};

int bpf_hw_setup_tc(struct net_device *dev, enum tc_setup_type type, void *type_data);

#endif /* _LINUX_NETDEV_HW_H */
