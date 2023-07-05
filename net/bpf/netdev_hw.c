// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/printk.h>
#include <linux/netdev_hw.h>

extern struct bpf_struct_ops bpf_net_device_hw_ops;

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
	return r;
}

static int bpf_hw_btf_struct_access(struct bpf_verifier_log *log,
				    const struct bpf_reg_state *reg,
				    int off, int size)
{
	printk(KERN_INFO "bpf_hw_btf_struct_access %d, %d\n", off, size);
	return 0;
}

static const struct bpf_verifier_ops  bpf_hw_verifier_ops = {
	.get_func_proto = bpf_hw_get_func_proto,
	.is_valid_access = bpf_hw_is_valid_access,
	.btf_struct_access = bpf_hw_btf_struct_access,
};

static int bpf_hw_reg(void *kdata)
{
	printk(KERN_INFO "bpf_hw_reg\n");
	return 0;
}

static void bpf_hw_unreg(void *kdata)
{
	printk(KERN_INFO "bpf_hw_unreg\n");
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
	printk(KERN_INFO "bpf_hw_check_member\n");
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
	printk(KERN_INFO "bpf_hw_init_member moff=%d, name=%lu\n",
	       moff, offsetof(struct net_device_hw_ops, name));
	switch (moff) {
	case offsetof(struct net_device_hw_ops, name):
		if (bpf_obj_name_cpy(ops->name, uops->name, sizeof(ops->name))
		    <= 0)
			return -EINVAL;
		return 1;
	}
	return 0;
}

static int bpf_hw_init(struct btf *btf)
{
	printk(KERN_INFO "bpf_hw_init\n");
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
