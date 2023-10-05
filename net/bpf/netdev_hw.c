// SPDX-License-Identifier: GPL-2.0

#include "asm-generic/errno.h"
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/printk.h>
#include <linux/netdev_hw.h>
#include <net/flow_offload.h>

extern struct bpf_struct_ops bpf_net_device_hw_ops;

static struct btf* kernel_btf;
static u32 flow_cls_offload_id;

static const struct bpf_func_proto *
bpf_hw_get_func_proto(enum bpf_func_id func_id,
		      const struct bpf_prog *prog)
{
	printk(KERN_INFO "bpf_hw_get_func_proto\n");
	return bpf_base_func_proto(func_id);
}

static bool bpf_hw_is_valid_access(int off, int size,
				   enum bpf_access_type type,
				   const struct bpf_prog *prog,
				   struct bpf_insn_access_aux *info)
{
	bool r = bpf_tracing_btf_ctx_access(off, size, type, prog, info);
	printk(KERN_INFO "bpf_hw_is_valid_access %d, %d, %d: %s\n",
	       off, size, type, r ? "true" : "false");

	if (info->btf && info->btf_id) {
		const struct btf_type * t =
			btf_type_by_id(info->btf, info->btf_id);
		const char *name =
			btf_name_by_offset(info->btf, t->name_off);
		printk(KERN_INFO "info type=0x%x, name=%s\n",
		       info->reg_type, name);
	} else {
		if (off == 8 && size == 8) {
			/* promote void* to struct flow_cls_offload* */
			info->btf = kernel_btf;
			info->btf_id = flow_cls_offload_id;
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;

			printk(KERN_INFO
			       "promoted to struct flow_cls_offload\n");
		}
	}

	return r;
}

static int bpf_hw_btf_struct_access(struct bpf_verifier_log *log,
				    const struct bpf_reg_state *reg,
				    int off, int size)
{
	const struct btf_type *t = btf_type_by_id(reg->btf, reg->btf_id);
	const char *name = btf_name_by_offset(reg->btf, t->name_off);
	printk(KERN_INFO "bpf_hw_btf_struct_access %s, %d, %d\n",
	       name, off, size);

	return PTR_TO_BTF_ID | PTR_TRUSTED;
}

static const struct bpf_verifier_ops  bpf_hw_verifier_ops = {
	.get_func_proto = bpf_hw_get_func_proto,
	.is_valid_access = bpf_hw_is_valid_access,
	.btf_struct_access = bpf_hw_btf_struct_access,
};

static int bpf_hw_reg(void *kdata, struct bpf_struct_ops_link *link)
{
	struct net_device *dev = bpf_struct_ops_link_get_device(link);
	printk(KERN_INFO "bpf_hw_reg: %s\n", dev->name);
	dev->hw_ops = kdata;
	return 0;
}

static void bpf_hw_unreg(void *kdata, struct bpf_struct_ops_link *link)
{
	struct net_device *dev = bpf_struct_ops_link_get_device(link);
	if (dev->hw_ops == kdata) {
		dev->hw_ops = NULL;
		printk(KERN_INFO "bpf_hw_unreg: %s successful\n", dev->name);
	} else {
		printk(KERN_INFO "bpf_hw_unreg: %s failed\n", dev->name);
	}
}

static int bpf_hw_update(void *kdata, void *old_kdata)
{
	printk(KERN_INFO "bpf_hw_update\n");
	return 0;
}

static int bpf_hw_check_member(const struct btf_type *t,
			       const struct btf_member *member,
			       const struct bpf_prog *prog)
{
	const char *name = btf_name_by_offset(prog->aux->attach_btf,
					      member->name_off);
	printk(KERN_INFO "bpf_hw_check_member name=%s, kind=%d\n",
	       name, BTF_INFO_KIND(t->type));
	return 0;
}

static int bpf_hw_init_member(const struct btf_type *t,
			      const struct btf_member *member,
			      void *kdata, const void *udata)
{
	const struct net_device_hw_ops *uops;
	struct net_device_hw_ops *ops;
	u32 moff;

	uops = (const struct net_device_hw_ops *)udata;
	ops = (struct net_device_hw_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct net_device_hw_ops, name):
		if (bpf_obj_name_cpy(ops->name,
				     uops->name,
				     sizeof(ops->name)) <= 0)
			return -EINVAL;
		return 1;
	}
	return 0;
}

static int bpf_hw_init(struct btf *btf)
{
	printk(KERN_INFO "bpf_hw_init\n");

	kernel_btf = btf;
	s32 type_id = btf_find_by_name_kind(btf, "flow_cls_offload",
					    BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	flow_cls_offload_id = type_id;
	return 0;
}

static int bpf_hw_validate(void *kdata)
{
	printk(KERN_INFO "bpf_hw_validate\n");
	return 0;
}

struct bpf_struct_ops bpf_net_device_hw_ops = {
	.verifier_ops = &bpf_hw_verifier_ops,
	.reg = bpf_hw_reg,
	.unreg = bpf_hw_unreg,
	.update = bpf_hw_update,
	.check_member = bpf_hw_check_member,
	.init_member = bpf_hw_init_member,
	.init = bpf_hw_init,
	.validate = bpf_hw_validate,
	.name = "net_device_hw_ops",
};


static LIST_HEAD(bpf_hw_block_ft_cb_list);
int bpf_hw_setup_tc(struct net_device *dev, enum tc_setup_type type,
		    void *type_data)
{
	const struct net_device_hw_ops *hw_ops = dev->hw_ops;
	struct flow_block_offload *f = type_data;
	void *priv = netdev_priv(dev);

	if (!hw_ops) {
		printk(KERN_INFO "No hw_ops registered with %s\n", dev->name);
		return -EOPNOTSUPP;
	}

	switch (type) {
	case TC_SETUP_FT:
		if (!hw_ops->setup_ft) {
			printk(KERN_INFO
			       "No setup_ft to call in hw_ops on %s\n",
			       dev->name);
			return -EOPNOTSUPP;
		}
		printk(KERN_INFO
		       "Calling flow_block_cb_setup_simple on %s, cmd=%s\n",
		       dev->name, f->command ? "unbind" : "bind");
		return flow_block_cb_setup_simple(type_data,
						  &bpf_hw_block_ft_cb_list,
						  hw_ops->setup_ft,
						  priv, priv, true);
	default:
		return -EOPNOTSUPP;
	}
}

EXPORT_SYMBOL(bpf_hw_setup_tc);
