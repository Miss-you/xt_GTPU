
/*
 * GTPu klm for Linux/iptables
 *
 * Copyright (c) 2015-? Polaris Networks
 * Author: yousa <snow_fly_dance@foxmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/slab.h> 
#include <linux/jhash.h>
#include <linux/sched.h>

#include "xt_GTPU.h"
#include "xt_GTPU_tab.h"

static int xt_GTPu_tab_down_bits = CONFIG_XTGTPU_TAB_BITS;

int xt_GTPu_tab_down_size __read_mostly;
static int xt_GTPu_tab_down_mask __read_mostly;

/* random value for GTPU connection hash */
static unsigned int xt_GTPu_tab_down_rnd __read_mostly;

/*
 *  Connection hash table: for output packets lookups of GTPU
 */
static struct hlist_head *xt_GTPu_tab_down __read_mostly;

/*  SLAB cache for GTPU connections */
static struct kmem_cache *xt_GTPu_tab_down_cachep __read_mostly;

/* lock array for conn table */
static struct xt_gtpu_aligned_lock
__xt_gtpu_tab_down_lock_array[CT_LOCKARRAY_SIZE] __cacheline_aligned;

static inline void ct_write_lock_bh_down(unsigned int key)
{
	spin_lock_bh(&__xt_gtpu_tab_down_lock_array[key&CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_unlock_bh_down(unsigned int key)
{
	spin_unlock_bh(&__xt_gtpu_tab_down_lock_array[key&CT_LOCKARRAY_MASK].l);
}

static inline bool __xt_gtpu_tab_down_get(struct xt_gtpu_tab_down_t *cp)
{
	return atomic_inc_not_zero(&cp->refcnt);
}

static inline void __xt_gtpu_tab_down_put(struct xt_gtpu_tab_down_t *cp)
{
	smp_mb__before_atomic_dec();
	atomic_dec(&(cp->refcnt));
}

static unsigned int xt_gtpu_tab_down_hashkey(const struct xt_gtpu_tab_down_param *p)
{
	return jhash_1word(p->UEip, xt_GTPu_tab_down_rnd) & xt_GTPu_tab_down_mask;
}

static unsigned int xt_gtpu_tab_down_hash_hashkey(struct xt_gtpu_tab_down_t *cp)
{
	struct xt_gtpu_tab_down_param p;
	xt_gtpu_tab_down_fill_param(cp->UEip, 0, 0, 0, 0, &p);/* enodeBip && teid is not used in xt_gtpu_tab_hashkey()*/

	return xt_gtpu_tab_down_hashkey(&p);
}

/*
 *	Hashes xt_gtpu_tab in xt_gtpu_tab_down by UEip
 *	returns bool success.
 */
static inline int xt_gtpu_tab_down_hash(struct xt_gtpu_tab_down_t *cp)
{
	unsigned int hash;
	int ret;

	/* Hash by protocol, client address and port */
	hash = xt_gtpu_tab_down_hash_hashkey(cp);
	//pr_info("gtpu: xt_gtpu_tab_hash hash = %d\n", hash);
	
	ct_write_lock_bh_down(hash);
	spin_lock(&cp->lock);
	
	atomic_inc(&cp->refcnt);
	hlist_add_head_rcu(&cp->c_list, &xt_GTPu_tab_down[hash]);
	ret = 1;

	spin_unlock(&cp->lock);
	ct_write_unlock_bh_down(hash);

	return ret;
}

static inline int xt_gtpu_tab_down_unhash(struct xt_gtpu_tab_down_t *cp)
{
	unsigned int hash;
	int ret;

	/* Hash by protocol, client address and port */
	hash = xt_gtpu_tab_down_hash_hashkey(cp);
	//pr_info("gtpu: xt_gtpu_tab_unhash hash = %d\n", hash);
	
	ct_write_lock_bh_down(hash);
	spin_lock(&cp->lock);

	/* may useful but don't know how to use it */
	//pr_info("gtpu: atomic_cmpxchg(&cp->refcnt, 1, 0) = %d\n", atomic_cmpxchg(&cp->refcnt, 1, 0));
	//if (atomic_cmpxchg(&cp->refcnt, 1, 0) == 1)
	{
		hlist_del_rcu(&(cp->c_list));
	//	pr_info("gtpu: hlist_del_rcu\n");
		ret = 1;
	}
	
	spin_unlock(&cp->lock);
	ct_write_unlock_bh_down(hash);

	return ret;
}

/* is inline suitable for xt_gtpu_tab_down_fill_param? */
void xt_gtpu_tab_down_fill_param(u32 UEip, u32 enodeBip, u32 enodeteid, u32 GWteid, u16 enodeBport, struct xt_gtpu_tab_down_param *p)
{
	p->UEip = UEip;
	p->enodeBip = enodeBip;
	p->enodeteid = enodeteid;
	p->GWteid = GWteid;
	p->enodeBport = enodeBport;
}

struct xt_gtpu_tab_down_t *
__xt_gtpu_tab_down_in_get(const struct xt_gtpu_tab_down_param *p)
{
	u32 hash;
	struct xt_gtpu_tab_down_t *cp;
	hash = xt_gtpu_tab_down_hashkey(p);

	rcu_read_lock();
	hlist_for_each_entry_rcu(cp, &xt_GTPu_tab_down[hash], c_list) 
	{
		if (p->UEip == cp->UEip) 
		{
			if (!__xt_gtpu_tab_down_get(cp))
			 	continue;

			rcu_read_unlock();
			return cp;
		}
	}

	rcu_read_unlock();

	return NULL;
}

/*
	free the xt_gtpu_tab_down node
*/
static void xt_gtpu_tab_down_rcu_free(struct rcu_head *head)
{
	struct xt_gtpu_tab_down_t *cp = container_of(head, struct xt_gtpu_tab_down_t,
					     rcu_head);

	kmem_cache_free(xt_GTPu_tab_down_cachep, cp);
}

/*
 *	When adding user into xt_gtpu_tab_down, adding a same UEip, just replace the old one
 */
static struct xt_gtpu_tab_down_t *
xt_gtpu_tab_down_add_replace(struct xt_gtpu_tab_down_t *old_cp, const struct xt_gtpu_tab_down_param *p)
{
	struct xt_gtpu_tab_down_t *new_cp;

	new_cp = kmem_cache_alloc(xt_GTPu_tab_down_cachep, GFP_ATOMIC);
	if (new_cp == NULL)
	{
		pr_err("kmem_cache_alloc no mem\n");
		return NULL;
	}

	/* init the new  xt_gtpu_tab_t */
	INIT_HLIST_NODE(&new_cp->c_list);

	new_cp->UEip = p->UEip;
	new_cp->enodeBip = p->enodeBip;
	new_cp->enodeteid = p->enodeteid;
	new_cp->GWteid = p->GWteid;
	new_cp->enodeBport = p->enodeBport;
	
	spin_lock_init(&new_cp->lock);

	atomic_set(&new_cp->refcnt, 1);
	atomic_set(&new_cp->pktaddcnt, 0);
	
	if (!__xt_gtpu_tab_down_get(old_cp))
	{
		return NULL;
	}
	hlist_replace_rcu(&(old_cp->c_list), &(new_cp->c_list));
	call_rcu(&(old_cp->rcu_head), xt_gtpu_tab_down_rcu_free);
	return new_cp;
}

/*
 *	Create a new connection entry and hash it into the xt_gtpu_tab_down
 */
struct xt_gtpu_tab_down_t *
xt_gtpu_tab_down_new(const struct xt_gtpu_tab_down_param *p)
{
	struct xt_gtpu_tab_down_t *cp;
	struct xt_gtpu_tab_down_t *old_cp;

	/* if add is repeat, just replace the old one */	
	old_cp = __xt_gtpu_tab_down_in_get(p);

	if (NULL == old_cp)
	{
		cp = kmem_cache_alloc(xt_GTPu_tab_down_cachep, GFP_ATOMIC);
		if (cp == NULL) {
			pr_err("kmem_cache_alloc no mem\n");
			return NULL;
		}

		INIT_HLIST_NODE(&cp->c_list);

		//pr_info("gtpu: p->UEip = %x\n", p->UEip);
		cp->UEip = p->UEip;
		cp->enodeBip = p->enodeBip;
		cp->enodeteid = p->enodeteid;
		cp->GWteid = p->GWteid;
		cp->enodeBport = p->enodeBport;
		
		spin_lock_init(&cp->lock);

		atomic_set(&cp->refcnt, 1);
		atomic_set(&cp->pktaddcnt, 0);
		
		/* Hash it in the ip_vs_conn_tab finally */
		xt_gtpu_tab_down_hash(cp);

		return cp;
	}
	else
	{
		cp = xt_gtpu_tab_down_add_replace(old_cp, p);

		return cp;
	}
}

/*
 * Create a new connection entry to replace the old entry
*/
struct xt_gtpu_tab_down_t *
xt_gtpu_tab_down_modify(const struct xt_gtpu_tab_down_param *p)
{
	struct xt_gtpu_tab_down_t *new_cp;
	struct xt_gtpu_tab_down_t *old_cp = NULL;
	u32 hash;

	new_cp = kmem_cache_alloc(xt_GTPu_tab_down_cachep, GFP_ATOMIC);
	if (new_cp == NULL)
	{
		pr_err("kmem_cache_alloc no mem\n");
		return NULL;
	}

	/* init the new  xt_gtpu_tab_down_t */
	INIT_HLIST_NODE(&new_cp->c_list);

	new_cp->UEip = p->UEip;
	new_cp->enodeBip = p->enodeBip;
	new_cp->enodeteid = p->enodeteid;
	new_cp->GWteid = p->GWteid;
	new_cp->enodeBport = p->enodeBport;
	
	spin_lock_init(&new_cp->lock);

	atomic_set(&new_cp->refcnt, 1);

	/* new_cp replace the old_cp */
	hash = xt_gtpu_tab_down_hashkey(p);

	hlist_for_each_entry_rcu(old_cp, &xt_GTPu_tab_down[hash], c_list) 
	{
		if (p->UEip == old_cp->UEip) 
		{
			if (!__xt_gtpu_tab_down_get(old_cp))
			{
				return NULL;
			}
			hlist_replace_rcu(&(old_cp->c_list), &(new_cp->c_list));
			call_rcu(&(old_cp->rcu_head), xt_gtpu_tab_down_rcu_free);
			return new_cp;
		}
	}
	return NULL;
}

//call_rcu(&cp->rcu_head, ip_vs_conn_rcu_free);
int
xt_gtpu_tab_down_delete(struct xt_gtpu_tab_down_t *cp)
{
	int ret = 0;
	xt_gtpu_tab_down_unhash(cp);

	call_rcu(&cp->rcu_head, xt_gtpu_tab_down_rcu_free);
	return ret;
}

int __init xt_gtpu_tab_down_init(void)
{
	int idx;

	/* Compute size and mask */
	xt_GTPu_tab_down_size = 1 << xt_GTPu_tab_down_bits;
	xt_GTPu_tab_down_mask = xt_GTPu_tab_down_size - 1;

	/*
	 * Allocate the connection hash table and initialize its list heads
	 */
	xt_GTPu_tab_down = vmalloc(xt_GTPu_tab_down_size * sizeof(*xt_GTPu_tab_down));
	if (!xt_GTPu_tab_down)
	{
		return -ENOMEM;
	}

	//struct xt_gtpu_tab_down_t
	/* Allocate ip_vs_conn slab cache */
	xt_GTPu_tab_down_cachep = kmem_cache_create("xt_GTPU_tab_down",
					      sizeof(struct xt_gtpu_tab_down_t), 0,
					      SLAB_HWCACHE_ALIGN, NULL);
	if (!xt_GTPu_tab_down_cachep) {
		vfree(xt_GTPu_tab_down);
		return -ENOMEM;
	}

	pr_info("Connection hash table configured "
		"(size=%d, memory=%ldKbytes)\n",
		xt_GTPu_tab_down_size,
		(long)(xt_GTPu_tab_down_size*sizeof(struct list_head))/1024);

	for (idx = 0; idx < xt_GTPu_tab_down_size; idx++)
		INIT_HLIST_HEAD(&xt_GTPu_tab_down[idx]);

	for (idx = 0; idx < CT_LOCKARRAY_SIZE; idx++)  {
		spin_lock_init(&__xt_gtpu_tab_down_lock_array[idx].l);
	}

	/* calculate the random value for connection hash */
	get_random_bytes(&xt_GTPu_tab_down_rnd, sizeof(xt_GTPu_tab_down_rnd));

	return 0;
}

void  xt_gtpu_tab_down_cleanup(void)
{
	/* Wait all rcu_free() callbacks to complete */
	rcu_barrier();
	/* Release the empty cache */
	kmem_cache_destroy(xt_GTPu_tab_down_cachep);
	vfree(xt_GTPu_tab_down);
}

