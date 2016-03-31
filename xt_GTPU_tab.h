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


#ifndef XT_GTPU_TAB_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/atomic.h>
#include <linux/ip.h>
#include <linux/route.h> 
#include <linux/types.h>
#include <linux/time.h>
#include <linux/u64_stats_sync.h>

#ifndef CONFIG_XTGTPU_TAB_BITS
#define CONFIG_XTGTPU_TAB_BITS 20
#endif

#ifndef CL_LOCKARRAY_DEF
#define CL_LOCKARRAY_BITS 5
#define CT_LOCKARRAY_SIZE (1<<CL_LOCKARRAY_BITS)
#define CT_LOCKARRAY_MASK (CT_LOCKARRAY_SIZE - 1)
#endif

#ifndef GTPU_SUCCESS_SEND
#define GTPU_SUCCESS_SEND 0 
#endif
 
#ifndef GTPU_FAILURE_SEND
#define GTPU_FAILURE_SEND -1 
#endif
 
#ifndef GTPU_INFO_SEND
#define GTPU_INFO_SEND 1 
#endif
 
 
#define NETLINK_TEST 17
#define GTPU_HDR_PNBIT 1
#define GTPU_HDR_SBIT 1 << 1
#define GTPU_HDR_EBIT 1 << 2
#define GTPU_ANY_EXT_HDR_BIT (GTPU_HDR_PNBIT | GTPU_HDR_SBIT | GTPU_HDR_EBIT)
 
#define GTPU_FAILURE 1
#define GTPU_SUCCESS !GTPU_FAILURE
 
#define GTPU_PORT 2152
#define GTPU_PTR2UINT(x) ((uint64_t)x) 
#define GTPU_VOID2CHARPTR(x) ((char *)x)

 enum xt_gtpu_inter_type
 {
	 kXtGTPUInterInsert,
	 kXtGTPUInterModify,
	 kXtGTPUInterDelete,
	 kXtGTPUInterInsertSuccess,
	 kXtGTPUInterModifySuccess,
	 kXtGTPUInterDeleteSuccess,
	 kXtGTPUInterInsertFailed,
	 kXtGTPUInterModifyFailed,
	 kXtGTPUInterDeleteFailed,
	 
	 kXtGTPUInterKernelCAU,  /* some info come from kernel 1st*/
	 kXtGTPUInterSetVirtIP,  /* set the xt_GTPU virtIP */
 
	 kXtGTPUDownPacketNotFound,
 
	 kXtGTPUInterTestSearchInsert,	/* test search */
	 kXtGTPUInterTestSearchInsertSuccess,
	 kXtGTPUInterTestSearchInsertFailed,

	 kXtGTPUInterStats,
	 kXtGTPUInterResetAllStats,
	 kXtGTPUInterResetErrorStats,
	 kXtGTPUInterGetErrorStats,
	 kXtGTPUInterGetErrorStatsInfo,

	 kXtGTPUInterPrintErrorStats,
 };
 
 struct xt_gtpu_inter_msg
 {
	 enum xt_gtpu_inter_type msgtype;
	 unsigned int UEip;
	 unsigned int enodeBip;
	 unsigned int enodeteid;
	 unsigned int GWteid;
	 unsigned short enodeBport;
 };
 
 struct xt_gtpu_inter_msg_stats_all
 {
	enum xt_gtpu_inter_type msgtype;
	
	__u32 uppkts;
	__u32 downpkts;
	__u64 upbytes;
	__u64 downbytes;

	__u32 uppps;
	__u32 downpps;
	__u64 upbps;
	__u64 downbps;

	__u32 alluppkts;
	__u32 alldownpkts;
 	__u32 erruppkts;
 	__u32 errdownpkts;
 };

 struct xt_gtpu_inter_msg_errorinfo_stats
{
	enum xt_gtpu_inter_type msgtype;
	
	__u32 GTPUerror_pkts;
	__u32 GTPUeNB_pkts;

	__u32 insert_success_num;
	__u32 insert_fail_num;
	__u32 modify_success_num;
	__u32 modify_fail_num;
	__u32 delete_success_num;
	__u32 delete_fail_num;
};
 
 struct gtpuhdr
 {
	 char flags;
	 char msgtype;
	 u_int16_t length;
	 u_int32_t tunid;
 };
 
 struct xt_gtpu_aligned_lock
 {
	 spinlock_t l;
 } __attribute__((__aligned__(SMP_CACHE_BYTES)));

 struct xt_gtpu_tab_down_t
 {
	 struct hlist_node c_list;
	 uint32_t UEip;				/* key value */
	 uint32_t enodeBip;
	 uint32_t enodeteid;
	 uint32_t GWteid;
	 uint16_t enodeBport;
	 atomic_t refcnt;
	 atomic_t pktaddcnt;
	 spinlock_t lock;			/* lock for state transition */
	 struct rcu_head rcu_head;
 };
 
 struct xt_gtpu_tab_down_param
 {
	 uint32_t UEip;
	 uint32_t enodeBip;
	 uint32_t enodeteid;
	 uint32_t GWteid;
	 uint16_t enodeBport;
 };

struct xt_gtpu_tab_up_t
{
	struct hlist_node c_list;
	uint32_t GWteid;				/* key value */
	uint32_t UEip;
	uint32_t enodeBip;
	uint16_t enodeBport;
	atomic_t refcnt;
	atomic_t pktrmcnt;
	spinlock_t lock;		   /* lock for state transition */
	struct rcu_head rcu_head;
};

struct xt_gtpu_tab_up_param
{
	uint32_t UEip;
	uint32_t enodeBip;
	uint32_t GWteid;
	uint16_t enodeBport;
};

/*
 * counters per cpu
 */
struct xt_gtpu_counters {
	__u32		erruppkts;	/* all send err incoming packets*/
	__u32		errdownpkts;/* all send err outgoing packets */
	__u32		alluppkts;  /* all incoming packets */
	__u32		alldownpkts;/* all outgoing packets */
	__u32		uppkts;		/* incoming packets */
	__u32		downpkts;	/* outgoing packets */
	__u64		upbytes;	/* incoming bytes */
	__u64		downbytes;	/* outgoing bytes */

	__u32		insert_success_num;/* insert user to hashtable success num */
	__u32		modify_success_num;/* modify user to hashtable success num */
	__u32		delete_success_num;/* delete user to hashtable success num */
};
/*
 * Stats per cpu
 */
struct xt_gtpu_cpu_stats {
	struct xt_gtpu_counters   ustats;
	struct u64_stats_sync   syncp;
};

/*
 *	xt_GTPU statistics objects
 */
struct xt_gtpu_estimator {
	struct list_head	list;

	u64			last_upbytes;
	u64			last_downbytes;
	u32			last_uppkts;
	u32			last_downpkts;

	u32			uppps;
	u32			downpps;
	u64			upbps;
	u64			downbps;
};

/*
 *	xt_GTPU statistics object (for user space)
 */
struct xt_gtpu_stats_user {
	__u32                   uppkts;         /* incoming packets */
	__u32                   downpkts;        /* outgoing packets */
	__u64                   upbytes;        /* incoming bytes */
	__u64                   downbytes;       /* outgoing bytes */
	__u32					alluppkts;
	__u32					alldownpkts;
	__u32					erruppkts;
	__u32					errdownpkts;

	__u32			uppps;		/* current in packet rate */
	__u32			downpps;		/* current out packet rate */
	__u64			upbps;		/* current in byte rate */
	__u64			downbps;		/* current out byte rate */
};

struct xt_gtpu_error_info_stats
{
	atomic_t			GTPUerror_cnt;
	atomic_t			GTPUeNB_cnt;

	atomic_t 			insert_fail_cnt;
	atomic_t 			modify_fail_cnt;
	atomic_t 			delete_fail_cnt;
};

struct xt_gtpu_stats {
	struct xt_gtpu_stats_user	ustats;		/* statistics */
	struct xt_gtpu_estimator	est;		/* estimator */
	struct xt_gtpu_cpu_stats __percpu	*cpustats;	/* per cpu counters */
	spinlock_t		lock;		/* spin lock */
	struct xt_gtpu_stats_user	ustats0;	/* reset values */
	struct xt_gtpu_error_info_stats		errinfo;	/* error info stats */
};

struct xt_gtpu_t
{
	/* xt_gtpu_ctl */
	struct xt_gtpu_stats tot_stats;
	
	/* xt_gtpu_est */
	struct list_head est_list;	/* estimator list */
	spinlock_t est_lock;
	struct timer_list est_timer; /* estimator timer */
};

/*
	xt_gtpu_tab_down declarations
*/
int xt_gtpu_tab_down_init(void);
void xt_gtpu_tab_down_cleanup(void);

void xt_gtpu_tab_down_fill_param(u32 UEip, u32 enodeBip, u32 enodeteid, u32 GWteid, u16 enodeBport, struct xt_gtpu_tab_down_param *p);
struct xt_gtpu_tab_down_t *xt_gtpu_tab_down_new(const struct xt_gtpu_tab_down_param *p);
struct xt_gtpu_tab_down_t *xt_gtpu_tab_down_modify(const struct xt_gtpu_tab_down_param *p);
struct xt_gtpu_tab_down_t *__xt_gtpu_tab_down_in_get(const struct xt_gtpu_tab_down_param *p);
int xt_gtpu_tab_down_delete(struct xt_gtpu_tab_down_t *cp);

/*
	xt_gtpu_tab_up declarations
*/
int xt_gtpu_tab_up_init(void);
void xt_gtpu_tab_up_cleanup(void);

void xt_gtpu_tab_up_fill_param(u32 UEip, u32 enodeBip, u32 GWteid, u16 enodeBport, struct xt_gtpu_tab_up_param *p);
struct xt_gtpu_tab_up_t *xt_gtpu_tab_up_new(const struct xt_gtpu_tab_up_param *p);
struct xt_gtpu_tab_up_t *xt_gtpu_tab_up_modify(const struct xt_gtpu_tab_up_param *p);
struct xt_gtpu_tab_up_t *__xt_gtpu_tab_up_in_get(const struct xt_gtpu_tab_up_param *p);
int xt_gtpu_tab_up_delete(struct xt_gtpu_tab_up_t *cp);

/*
	xt_gtpu_est declarations
*/
int xt_gtpu_estimator_init(struct xt_gtpu_t *xt_gtpu);
void xt_gtpu_estimator_cleanup(struct xt_gtpu_t *xt_gtpu);
void xt_gtpu_start_estimator(struct xt_gtpu_t *xt_gtpu, struct xt_gtpu_stats *stats);
void xt_gtpu_stop_estimator(struct xt_gtpu_t *xt_gtpu, struct xt_gtpu_stats *stats);
void xt_gtpu_zero_estimator(struct xt_gtpu_stats *stats);
void xt_gtpu_read_estimator(struct xt_gtpu_stats_user *dst, struct xt_gtpu_stats *stats);
void xt_gtpu_read_cpu_error_stats(struct xt_gtpu_inter_msg_errorinfo_stats *sum,
										struct xt_gtpu_cpu_stats __percpu *per_cpu_stats);

/*
	xt_gtpu_core declarations
*/
unsigned int xt_gtpu_send_statsmsg(char *statsMsg, unsigned int msg_len);

#endif
