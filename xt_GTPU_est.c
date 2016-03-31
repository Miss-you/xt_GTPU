
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

#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/sysctl.h>
#include <linux/list.h>

#include "xt_GTPU.h"
#include "xt_GTPU_tab.h"

/*
  This code is to estimate rate in a shorter interval (such as 8
  seconds) for virtual services and real servers. For measure rate in a
  long interval, it is easy to implement a user level daemon which
  periodically reads those statistical counters and measure rate.

  Currently, the measurement is activated by slow timer handler. Hope
  this measurement will not introduce too much load.

  We measure rate during the last 8 seconds every 2 seconds:

    avgrate = avgrate*(1-W) + rate*W

    where W = 2^(-2)

  NOTES.

  * The stored value for average bps is scaled by 2^5, so that maximal
    rate is ~2.15Gbits/s, average pps and cps are scaled by 2^10.

  * A lot code is taken from net/sched/estimator.c
 */

/* 
	avgrate = avgrate*(1-W) + rate*W
	where W = 2^(-2) 
*/
//#define XT_GTPU_EST_AVGRATE
/* where W = (pkt - last_pkt) >> 1 */
#define XT_GTPU_EST_AVRAGE

static void inline
xt_gtpu_read_estimator_2statsmsg(struct xt_gtpu_inter_msg_stats_all *dst,
			  struct xt_gtpu_estimator *estimator)
{
	dst->uppps = (estimator->uppps + 0x1FF) >> 10;
	dst->downpps = (estimator->downpps + 0x1FF) >> 10;
	dst->upbps = (estimator->upbps + 0xF) >> 5;
	dst->downbps = (estimator->downbps + 0xF) >> 5;
}

/* not used now */
static void
xt_gtpu_copy_stats(struct xt_gtpu_stats_user *dst, struct xt_gtpu_stats *src)
{
#define XT_GTPU_SHOW_STATS_COUNTER(c) dst->c = src->ustats.c - src->ustats0.c

	spin_lock_bh(&src->lock);

	XT_GTPU_SHOW_STATS_COUNTER(uppkts);
	XT_GTPU_SHOW_STATS_COUNTER(downpkts);
	XT_GTPU_SHOW_STATS_COUNTER(upbytes);
	XT_GTPU_SHOW_STATS_COUNTER(downbytes);

	XT_GTPU_SHOW_STATS_COUNTER(alluppkts);
	XT_GTPU_SHOW_STATS_COUNTER(alldownpkts);
	XT_GTPU_SHOW_STATS_COUNTER(erruppkts);
	XT_GTPU_SHOW_STATS_COUNTER(errdownpkts);

	xt_gtpu_read_estimator(dst, src);

	spin_unlock_bh(&src->lock);
}

static void 
xt_gtpu_init_stats(struct xt_gtpu_stats *stats)
{
	spin_lock_bh(&stats->lock);

	/* init the stats */
#define XT_GTPU_INIT_STATS_COUNTER(c) stats->ustats.c = 0;
#define XT_GTPU_INIT_STATS0_COUNTER(c) stats->ustats0.c = 0;

	XT_GTPU_INIT_STATS_COUNTER(uppkts);
	XT_GTPU_INIT_STATS_COUNTER(downpkts);
	XT_GTPU_INIT_STATS_COUNTER(upbytes);
	XT_GTPU_INIT_STATS_COUNTER(downbytes);
	XT_GTPU_INIT_STATS_COUNTER(uppps);
	XT_GTPU_INIT_STATS_COUNTER(downpps);
	XT_GTPU_INIT_STATS_COUNTER(upbps);
	XT_GTPU_INIT_STATS_COUNTER(downbps);
	XT_GTPU_INIT_STATS_COUNTER(alluppkts);
	XT_GTPU_INIT_STATS_COUNTER(alldownpkts);
	XT_GTPU_INIT_STATS_COUNTER(erruppkts);
	XT_GTPU_INIT_STATS_COUNTER(errdownpkts);

	XT_GTPU_INIT_STATS0_COUNTER(uppkts);
	XT_GTPU_INIT_STATS0_COUNTER(downpkts);
	XT_GTPU_INIT_STATS0_COUNTER(upbytes);
	XT_GTPU_INIT_STATS0_COUNTER(downbytes);
	XT_GTPU_INIT_STATS0_COUNTER(uppps);
	XT_GTPU_INIT_STATS0_COUNTER(downpps);
	XT_GTPU_INIT_STATS0_COUNTER(upbps);
	XT_GTPU_INIT_STATS0_COUNTER(downbps);
	XT_GTPU_INIT_STATS0_COUNTER(alluppkts);
	XT_GTPU_INIT_STATS0_COUNTER(alldownpkts);
	XT_GTPU_INIT_STATS0_COUNTER(erruppkts);
	XT_GTPU_INIT_STATS0_COUNTER(errdownpkts);

	xt_gtpu_zero_estimator(stats);

	spin_unlock_bh(&stats->lock);
}

/* not used now */
static void
xt_gtpu_zero_stats(struct xt_gtpu_stats *stats)
{
	spin_lock_bh(&stats->lock);

	/* get current counters as zero point, rates are zeroed */

#define XT_GTPU_ZERO_STATS_COUNTER(c) stats->ustats0.c = stats->ustats.c

	XT_GTPU_ZERO_STATS_COUNTER(uppkts);
	XT_GTPU_ZERO_STATS_COUNTER(downpkts);
	XT_GTPU_ZERO_STATS_COUNTER(upbytes);
	XT_GTPU_ZERO_STATS_COUNTER(downbytes);
	XT_GTPU_ZERO_STATS_COUNTER(alluppkts);
	XT_GTPU_ZERO_STATS_COUNTER(alldownpkts);
	XT_GTPU_ZERO_STATS_COUNTER(erruppkts);
	XT_GTPU_ZERO_STATS_COUNTER(errdownpkts);

	xt_gtpu_zero_estimator(stats);

	spin_unlock_bh(&stats->lock);
}

/* Make a error info summary from each cpu */
void 
xt_gtpu_read_cpu_error_stats(struct xt_gtpu_inter_msg_errorinfo_stats *sum,
										struct xt_gtpu_cpu_stats __percpu *per_cpu_stats)
{
	int i;
	bool add = false;

	for_each_possible_cpu(i) {
		struct xt_gtpu_cpu_stats *stats = per_cpu_ptr(per_cpu_stats, i);
		if (add) {
			sum->insert_success_num += stats->ustats.insert_success_num;
			sum->modify_success_num += stats->ustats.modify_success_num;
			sum->delete_success_num += stats->ustats.delete_success_num;
		} else {
			add = true;
			sum->insert_success_num = stats->ustats.insert_success_num;
			sum->modify_success_num = stats->ustats.modify_success_num;
			sum->delete_success_num = stats->ustats.delete_success_num;
		}
	}
}

/*
 * Make a summary from each cpu
 */
static void 
xt_gtpu_read_cpu_stats(struct xt_gtpu_stats_user *sum,
				 struct xt_gtpu_cpu_stats __percpu *per_cpu_stats)
{
	int i;
	bool add = false;
	
	for_each_possible_cpu(i) {
		struct xt_gtpu_cpu_stats *stats = per_cpu_ptr(per_cpu_stats, i);
		unsigned int start;
		__u64 upbytes, downbytes;
		if (add) {
			sum->uppkts += stats->ustats.uppkts;
			sum->downpkts += stats->ustats.downpkts;
			sum->alluppkts += stats->ustats.alluppkts;
			sum->alldownpkts += stats->ustats.alldownpkts;
			sum->erruppkts += stats->ustats.erruppkts;
			sum->errdownpkts += stats->ustats.errdownpkts;
			do {
				start = u64_stats_fetch_begin(&stats->syncp);
				upbytes = stats->ustats.upbytes;
				downbytes = stats->ustats.downbytes;
			} while (u64_stats_fetch_retry(&stats->syncp, start));
			sum->upbytes += upbytes;
			sum->downbytes += downbytes;
		} else {
			add = true;
			sum->uppkts = stats->ustats.uppkts;
			sum->downpkts = stats->ustats.downpkts;
			sum->alluppkts = stats->ustats.alluppkts;
			sum->alldownpkts = stats->ustats.alldownpkts;
			sum->erruppkts = stats->ustats.erruppkts;
			sum->errdownpkts = stats->ustats.errdownpkts;
			do {
				start = u64_stats_fetch_begin(&stats->syncp);
				sum->upbytes = stats->ustats.upbytes;
				sum->downbytes = stats->ustats.downbytes;
			} while (u64_stats_fetch_retry(&stats->syncp, start));
		}
	}
}

static void 
estimation_timer(unsigned long arg)
{
	struct xt_gtpu_estimator *estimator;
	struct xt_gtpu_stats *stats;
	u32 n_uppkts = 0, n_downpkts = 0;
	u64 n_upbytes = 0, n_downbytes = 0;
	u32 n_alluppkts = 0, n_alldownpkts = 0;
	u32 n_erruppkts = 0, n_errdownpkts = 0;
#ifdef XT_GTPU_EST_AVGRATE
	u32 rate;
#endif
	struct xt_gtpu_t *xt_gtpu = (struct xt_gtpu_t *)arg;
	struct xt_gtpu_inter_msg_stats_all statsMsg;

	spin_lock(&xt_gtpu->est_lock);
	list_for_each_entry(estimator, &xt_gtpu->est_list, list) {
		stats = container_of(estimator, struct xt_gtpu_stats, est);

		spin_lock(&stats->lock);
		xt_gtpu_read_cpu_stats(&stats->ustats, stats->cpustats);
		n_uppkts = stats->ustats.uppkts;
		n_downpkts = stats->ustats.downpkts;
		n_upbytes = stats->ustats.upbytes;
		n_downbytes = stats->ustats.downbytes;
		n_alluppkts = stats->ustats.alluppkts;
		n_alldownpkts = stats->ustats.alldownpkts;
		n_erruppkts = stats->ustats.erruppkts;
		n_errdownpkts = stats->ustats.errdownpkts;
		
#ifdef XT_GTPU_EST_AVGRATE
		/* scaled by 2^10, but divided 2 seconds */
		rate = (n_uppkts - estimator->last_uppkts) << 9;
		estimator->last_uppkts = n_uppkts;
		estimator->uppps += ((long)rate - (long)estimator->uppps) >> 2;
		
		rate = (n_downpkts - estimator->last_downpkts) << 9;
		estimator->last_downpkts = n_downpkts;
		estimator->downpps += ((long)rate - (long)estimator->downpps) >> 2;

		rate = (n_upbytes - estimator->last_upbytes) << 4;
		estimator->last_upbytes = n_upbytes;
		estimator->upbps += ((long)rate - (long)estimator->upbps) >> 2;
		
		rate = (n_downbytes - estimator->last_downbytes) << 4;
		estimator->last_downbytes = n_downbytes;
		estimator->downbps += ((long)rate - (long)estimator->downbps) >> 2;
#endif

#ifdef XT_GTPU_EST_AVRAGE
		estimator->uppps = (n_uppkts - estimator->last_uppkts) >> 1;
		estimator->last_uppkts = n_uppkts;

		estimator->downpps = (n_downpkts - estimator->last_downpkts) >> 1;
		estimator->last_downpkts = n_downpkts;

		estimator->upbps = (n_upbytes - estimator->last_upbytes) >> 1;
		estimator->last_upbytes = n_upbytes;

		estimator->downbps = (n_downbytes - estimator->last_downbytes) >> 1;
		estimator->last_downbytes = n_downbytes;
#endif
		spin_unlock(&stats->lock);
		/* fill stats msg to userspace */
		statsMsg.uppkts = n_uppkts;
		statsMsg.downpkts = n_downpkts;
		statsMsg.upbytes = n_upbytes;
		statsMsg.downbytes = n_downbytes;
		statsMsg.alluppkts = n_alluppkts;
		statsMsg.erruppkts = n_erruppkts;
		statsMsg.alldownpkts = n_alldownpkts;
		statsMsg.errdownpkts = n_errdownpkts;
		
#ifdef XT_GTPU_EST_AVGRATE
		xt_gtpu_read_estimator_2statsmsg(&statsMsg, estimator);
#endif

#ifdef XT_GTPU_EST_AVRAGE
		statsMsg.uppps = estimator->uppps;
		statsMsg.downpps = estimator->downpps;
		statsMsg.upbps = estimator->upbps;
		statsMsg.downbps = estimator->downbps;
#endif
	}
	spin_unlock(&xt_gtpu->est_lock);

	/* send stats msg to userspace */
	statsMsg.msgtype = kXtGTPUInterStats;
	xt_gtpu_send_statsmsg(GTPU_VOID2CHARPTR(&statsMsg), sizeof(struct xt_gtpu_inter_msg_stats_all));
	mod_timer(&xt_gtpu->est_timer, jiffies + 2*HZ);
}

void xt_gtpu_start_estimator(struct xt_gtpu_t *xt_gtpu, struct xt_gtpu_stats *stats)
{
	struct xt_gtpu_estimator *est = &stats->est;

	INIT_LIST_HEAD(&est->list);

	spin_lock_bh(&xt_gtpu->est_lock);
	list_add(&est->list, &xt_gtpu->est_list);
	spin_unlock_bh(&xt_gtpu->est_lock);
}

void xt_gtpu_stop_estimator(struct xt_gtpu_t *xt_gtpu, struct xt_gtpu_stats *stats)
{
	struct xt_gtpu_estimator *est = &stats->est;

	spin_lock_bh(&xt_gtpu->est_lock);
	list_del(&est->list);
	spin_unlock_bh(&xt_gtpu->est_lock);
}

void xt_gtpu_zero_estimator(struct xt_gtpu_stats *stats)
{
	struct xt_gtpu_estimator *estimator = &stats->est;
	struct xt_gtpu_stats_user *user = &stats->ustats;

	/* reset counters, caller must hold the stats->lock lock */
	estimator->last_upbytes = user->upbytes;
	estimator->last_downbytes = user->downbytes;
	estimator->last_uppkts = user->uppkts;
	estimator->last_downpkts = user->downpkts;
	estimator->uppps = 0;
	estimator->downpps = 0;
	estimator->upbps = 0;
	estimator->downbps = 0;
}

/* Get decoded rates */
void xt_gtpu_read_estimator(struct xt_gtpu_stats_user *dst,
			  struct xt_gtpu_stats *stats)
{
	struct xt_gtpu_estimator *estimator = &stats->est;

	dst->uppps = (estimator->uppps + 0x1FF) >> 10;
	dst->downpps = (estimator->downpps + 0x1FF) >> 10;
	dst->upbps = (estimator->upbps + 0xF) >> 5;
	dst->downbps = (estimator->downbps + 0xF) >> 5;
}

int __init xt_gtpu_estimator_init(struct xt_gtpu_t *xt_gtpu)
{
	int i;
	
	INIT_LIST_HEAD(&(xt_gtpu->est_list));
	spin_lock_init(&(xt_gtpu->est_lock));
	setup_timer(&xt_gtpu->est_timer, estimation_timer, (unsigned long)xt_gtpu);
	mod_timer(&xt_gtpu->est_timer, jiffies + 2*HZ);

	/* procfs stats */
	xt_gtpu->tot_stats.cpustats = alloc_percpu(struct xt_gtpu_cpu_stats);
	if (!xt_gtpu->tot_stats.cpustats)
		return -ENOMEM;

	for_each_possible_cpu(i) {
		struct xt_gtpu_cpu_stats *xt_gtpu_tot_stats;
		xt_gtpu_tot_stats = per_cpu_ptr(xt_gtpu->tot_stats.cpustats, i);
		u64_stats_init(&xt_gtpu_tot_stats->syncp);
		
		xt_gtpu_tot_stats->ustats.uppkts = 0;
		xt_gtpu_tot_stats->ustats.downpkts = 0;
		xt_gtpu_tot_stats->ustats.upbytes = 0;
		xt_gtpu_tot_stats->ustats.downbytes = 0;
		xt_gtpu_tot_stats->ustats.alluppkts = 0;
		xt_gtpu_tot_stats->ustats.alldownpkts = 0;
		xt_gtpu_tot_stats->ustats.erruppkts = 0;
		xt_gtpu_tot_stats->ustats.errdownpkts = 0;
	}

	spin_lock_init(&xt_gtpu->tot_stats.lock);
	
	xt_gtpu_init_stats(&xt_gtpu->tot_stats);
	xt_gtpu_start_estimator(xt_gtpu, &xt_gtpu->tot_stats);
	return 0;
}

void xt_gtpu_estimator_cleanup(struct xt_gtpu_t *xt_gtpu)
{
	xt_gtpu_stop_estimator(xt_gtpu, &xt_gtpu->tot_stats);

	free_percpu(xt_gtpu->tot_stats.cpustats);
	
	del_timer_sync(&xt_gtpu->est_timer);
}
