
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

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netlink.h>
#include <linux/sched.h>
#include <linux/highmem.h>

#include <net/checksum.h>
#include <net/udp.h>
#include <net/inet_sock.h>
#include <net/ip.h>
#include <net/route.h> 
#include <net/sock.h>

#include "xt_GTPU.h"
#include "xt_GTPU_tab.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pradip Biswas <pradip_biswas@polarisnetworks.net>");
MODULE_DESCRIPTION("GTPu Data Path extension on netfilter");

/*test compile opt	*/
//#define LH_DO_GETTIMEOFDAY

//#define LH_TEST_CASE_HASHTAB
//#define LH_TEST_DEBUG_PRINT
//#define LH_TEST_GETTEID

static struct sock *netlinkfd = NULL;

struct {
	__u32 pid;
}g_user_process;

/* GTPU virtual IP */
//for LVS
__be32 g_xt_GTPU_kernel_virtual_IP __read_mostly;

/* GTPU global struct var */
//for stats
struct xt_gtpu_t g_xt_GTPU_stats __read_mostly;

static inline struct net *
xt_gtpu_skb_net(const struct sk_buff *skb)
{
	return &init_net;
}

static inline void xt_gtpu_inter_set_virtual_IP(unsigned int virtIP)
{
	g_xt_GTPU_kernel_virtual_IP = virtIP;
}

/* 
************************************************************************
g_xt_GTPU_stats 

GTPU transmit pkts stats
************************************************************************
*/
//upload GTPU pkt stats
static inline void
xt_gtpu_up_stats(struct xt_gtpu_t *xt_gtpu, struct sk_buff *skb)
{
	struct xt_gtpu_cpu_stats *stats;

	stats = this_cpu_ptr(xt_gtpu->tot_stats.cpustats);
	stats->ustats.uppkts++;
	u64_stats_update_begin(&stats->syncp);
	stats->ustats.upbytes += skb->len;
	u64_stats_update_end(&stats->syncp);
}

//download GTPU pkt stats
static inline void
xt_gtpu_down_stats(struct xt_gtpu_t *xt_gtpu, struct sk_buff *skb)
{
	struct xt_gtpu_cpu_stats *stats;

	stats = this_cpu_ptr(xt_gtpu->tot_stats.cpustats);
	stats->ustats.downpkts++;
	u64_stats_update_begin(&stats->syncp);
	stats->ustats.downbytes += skb->len;
	u64_stats_update_end(&stats->syncp);
}

/* xt_gtpu stats all pkts */
//upload GTPU pkt stats(enclude pkts failed)
static inline void
xt_gtpu_up_stats_all(struct xt_gtpu_t *xt_gtpu, struct sk_buff *skb)
{
	struct xt_gtpu_cpu_stats *stats;

	stats = this_cpu_ptr(xt_gtpu->tot_stats.cpustats);
	stats->ustats.alluppkts++;
}

//download GTPU pkt stats(enclude pkts failed)
static inline void
xt_gtpu_down_stats_all(struct xt_gtpu_t *xt_gtpu, struct sk_buff *skb)
{
	struct xt_gtpu_cpu_stats *stats;

	stats = this_cpu_ptr(xt_gtpu->tot_stats.cpustats);
	stats->ustats.alldownpkts++;
}

/* xt_gtpu stats all pkts */
//upload GTPU error pkt stats
static inline void
xt_gtpu_up_stats_err(struct xt_gtpu_t *xt_gtpu, struct sk_buff *skb)
{
	struct xt_gtpu_cpu_stats *stats;

	stats = this_cpu_ptr(xt_gtpu->tot_stats.cpustats);
	stats->ustats.erruppkts++;
}

//download GTPU error pkt stats
static inline void
xt_gtpu_down_stats_err(struct xt_gtpu_t *xt_gtpu, struct sk_buff *skb)
{
	struct xt_gtpu_cpu_stats *stats;

	stats = this_cpu_ptr(xt_gtpu->tot_stats.cpustats);
	stats->ustats.errdownpkts++;
}

/* 
************************************************************************
g_xt_GTPU_stats 

up/down transmit-table insert/modify/delete stats
************************************************************************
*/
#define XT_GTPU_INTER_INSERTCNT(ret) \
	do{\
		if (likely(ret == 0))\
		{\
			xt_gtpu_stats_insertsuccessnum(&g_xt_GTPU_stats);\
		}\
		else\
		{\
			xt_gtpu_stats_insertfailnum(&g_xt_GTPU_stats);\
		}\
	}while(0)

#define XT_GTPU_INTER_MODIFYCNT(ret) \
	do{\
		if (likely(ret == 0))\
		{\
			xt_gtpu_stats_modifysuccessnum(&g_xt_GTPU_stats);\
		}\
		else\
		{\
			xt_gtpu_stats_modifyfailnum(&g_xt_GTPU_stats);\
		}\
	}while(0)

#define XT_GTPU_INTER_DELETECNT(ret) \
	do{\
		if (likely(ret == 0))\
		{\
			xt_gtpu_stats_deletesuccessnum(&g_xt_GTPU_stats);\
		}\
		else\
		{\
			xt_gtpu_stats_deletefailnum(&g_xt_GTPU_stats);\
		}\
	}while(0)

static inline void
xt_gtpu_stats_insertsuccessnum(struct xt_gtpu_t *xt_gtpu)
{
	struct xt_gtpu_cpu_stats *stats;

	stats = this_cpu_ptr(xt_gtpu->tot_stats.cpustats);
	stats->ustats.insert_success_num++;
}

static inline void
xt_gtpu_stats_insertfailnum(struct xt_gtpu_t *xt_gtpu)
{
	struct xt_gtpu_error_info_stats *errinfo;

	errinfo = &(xt_gtpu->tot_stats.errinfo);
	atomic_inc(&(errinfo->insert_fail_cnt));
}

static inline void
xt_gtpu_stats_modifysuccessnum(struct xt_gtpu_t *xt_gtpu)
{
	struct xt_gtpu_cpu_stats *stats;

	stats = this_cpu_ptr(xt_gtpu->tot_stats.cpustats);
	stats->ustats.modify_success_num++;
}

static inline void
xt_gtpu_stats_modifyfailnum(struct xt_gtpu_t *xt_gtpu)
{
	struct xt_gtpu_error_info_stats *errinfo;

	errinfo = &(xt_gtpu->tot_stats.errinfo);
	atomic_inc(&(errinfo->modify_fail_cnt));
}

static inline void
xt_gtpu_stats_deletesuccessnum(struct xt_gtpu_t *xt_gtpu)
{
	struct xt_gtpu_cpu_stats *stats;

	stats = this_cpu_ptr(xt_gtpu->tot_stats.cpustats);
	stats->ustats.delete_success_num++;
}

static inline void
xt_gtpu_stats_deletefailnum(struct xt_gtpu_t *xt_gtpu)
{
	struct xt_gtpu_error_info_stats *errinfo;

	errinfo = &(xt_gtpu->tot_stats.errinfo);
	atomic_inc(&(errinfo->delete_fail_cnt));
}

/* 
************************************************************************
get GTPU pkts TEID or GTPU-type

xt_gtpu_get_GTPUtype
xt_gtpu_get_GTPUteid
************************************************************************
*/
#define TEID_TYPE_OFFSET 28
#define GTPU_PKT_TPU_TYPE 0xff
#define GTPU_PKT_ERRINDICATION_TYPE 0x1a
static const int xt_gtpu_get_GTPUtype_offset = TEID_TYPE_OFFSET - sizeof(struct iphdr) - sizeof(struct udphdr);

/* 0 is T-PDU, GTPU data
*  1 is Error Indication
*  -1 is unknow type
*/
static uint8_t
xt_gtpu_get_GTPUtype(const struct sk_buff *skb)
{
	uint8_t GTPUtype;
	int skb_head_len;
	/* 1st condition, teid is in skb_buff */
	if (!skb_is_nonlinear(skb))
	{
		GTPUtype = *(uint8_t *)(skb->data + TEID_TYPE_OFFSET + 1);
		/*
		pr_info("%x %x %x %x\n", *(uint8_t *)(skb->data + TEID_TYPE_OFFSET), \
			*(uint8_t *)(skb->data + TEID_TYPE_OFFSET + 1),\
			*(uint8_t *)(skb->data + TEID_TYPE_OFFSET + 2),\
			*(uint8_t *)(skb->data + TEID_TYPE_OFFSET + 3));
		*/
		goto GTPUtypeJudge;
	}
	else
	{
		char *vaddr;
		struct page *page;
		int i = 0;
		skb_frag_t *frag;
		int offset;

		/* 2nd condition, teid is still in skb_buff */
		skb_head_len = skb->len - skb->data_len;
		if (unlikely(skb_head_len >= (TEID_TYPE_OFFSET+4)))
		{
			GTPUtype = *(uint8_t *)(skb->data + TEID_TYPE_OFFSET + 1);
			goto GTPUtypeJudge;
		}
		
		/* 3rd condition, teid is in the page of the skb_shinfo(skb)->frags[i]  */
		frag = &(skb_shinfo(skb)->frags[i]);
		
		offset = xt_gtpu_get_GTPUtype_offset;
		for(;offset >= frag->size;)
		{
			++i;
			offset = offset - frag->size;
			frag = &(skb_shinfo(skb)->frags[i]);
			printk(KERN_ALERT "gtpu: page[%d] full.\n", i);
		}
		
		page = frag->page.p;
		vaddr = (char *)kmap(page);
		GTPUtype = *(uint8_t *)(vaddr + frag->page_offset + offset + 1);
		
GTPUtypeJudge:
		return GTPUtype;
	}
}

#define TEID_VALUE_OFFSET 32
static const int xt_gtpu_gett_teid_offset = TEID_VALUE_OFFSET - sizeof(struct iphdr) - sizeof(struct udphdr);

static unsigned int 
xt_gtpu_get_GTPUteid(const struct sk_buff *skb)
{
#ifdef LH_TEST_GETTEID
	int test_offset;
	int i;
	struct sk_buff *list;
#endif
	
	unsigned int teid;
	int skb_head_len;
	/* 1st condition, teid is in skb_buff */
	if (!skb_is_nonlinear(skb))
	{
	
#ifdef LH_TEST_GETTEID
		pr_info("skb is linear\n");
#endif

		teid = *(unsigned int *)(skb->data + TEID_VALUE_OFFSET);
		return teid;
	}
	else
	{	
		char *vaddr;
		struct page *page;
		int i = 0;
		skb_frag_t *frag;
		int offset;
		
#ifdef LH_TEST_GETTEID
		pr_info("skb is nonlinear\n");
		//sk_buff->data_len
		pr_info("skb data_len is %d\n", skb->data_len);
		pr_info("skb len is %d\n", skb->len);
		pr_info("skb truesize is %d\n", skb->truesize);
		pr_info("linear teid is %x\n", *(unsigned int *)(skb->data + TEID_VALUE_OFFSET));
#endif

		/* 2nd condition, teid is still in skb_buff */
		skb_head_len = skb->len - skb->data_len;
		if (unlikely(skb_head_len >= (TEID_VALUE_OFFSET+4)))
		{
			teid = *(unsigned int *)(skb->data + TEID_VALUE_OFFSET);
			return teid;
		}
		
		/* 3rd condition, teid is in the page of the skb_shinfo(skb)->frags[i]  */
		frag = &(skb_shinfo(skb)->frags[i]);
		
		offset = xt_gtpu_gett_teid_offset;
		for(;offset >= frag->size;)
		{
			++i;
			offset = offset - frag->size;
			frag = &(skb_shinfo(skb)->frags[i]);
			printk(KERN_ALERT "gtpu: page[%d] full.\n", i);
		}
		
		page = frag->page.p;
		vaddr = (char *)kmap(page);
		teid = *(unsigned int *)(vaddr + frag->page_offset + offset);
		
#ifdef LH_TEST_GETTEID
		list = skb_shinfo(skb)->frag_list;
		if (list != NULL)
		{
			pr_info("list is not NULL, list size is %d\n", list->truesize);
		}
#endif
		return teid;
	}
}

/* 
************************************************************************
netlink sock receive/send/handle-msg

used for control the xt_GTPU and insert/modify/delete xt_GTPU_tab
or reset stats
************************************************************************
*/
//insert a user-info to xt_GTPU_tab
static int xt_gtpu_inter_insert(struct xt_gtpu_tab_down_param *p, struct xt_gtpu_tab_up_param *p_up)
{
	struct xt_gtpu_tab_down_t* cp = NULL;
	struct xt_gtpu_tab_up_t* cp_up = NULL;
	int ret = -1;

#ifdef LH_TEST_DEBUG_PRINT
	pr_info("gtpu: insert-p:UEip = %d", p->UEip);
	pr_info("gtpu: insert-p:enodeBip = %d", p->enodeBip);
	pr_info("gtpu: insert-p:enodeteid = %d", p->enodeteid);
	pr_info("gtpu: insert-p:GWteid = %d", p->GWteid);
	pr_info("gtpu: insert-p:enodeBport = %d", p->enodeBport);
#endif

	cp_up = xt_gtpu_tab_up_new(p_up);
	cp = xt_gtpu_tab_down_new(p);

	if (NULL == cp || NULL == cp_up)
	{
		pr_err("gtpu: xt_gtpu_tab_down_new failed\n");
		ret = -1;
		if (NULL != cp)
		{
			xt_gtpu_tab_down_delete(cp);
		}
		if (NULL != cp_up)
		{
			xt_gtpu_tab_up_delete(cp_up);
		}
	}
	ret = 0;

	XT_GTPU_INTER_INSERTCNT(ret);
	return ret;
}

//modify a user-info to xt_GTPU_tab
static int xt_gtpu_inter_modify(struct xt_gtpu_tab_down_param *p, struct xt_gtpu_tab_up_param *p_up)
{
	struct xt_gtpu_tab_down_t* cp = NULL;
	struct xt_gtpu_tab_up_t* cp_up = NULL;
	int ret = -1;

#ifdef LH_TEST_DEBUG_PRINT
	pr_info("gtpu: modify-p:UEip = %d", p->UEip);
	pr_info("gtpu: modify-p:enodeBip = %d", p->enodeBip);
	pr_info("gtpu: modify-p:enodeteid = %d", p->enodeteid);
	pr_info("gtpu: modify-p:GWteid = %d", p->GWteid);
	pr_info("gtpu: modify-p:enodeBport = %d", p->enodeBport);
#endif

	cp_up = xt_gtpu_tab_up_modify(p_up);
	cp = xt_gtpu_tab_down_modify(p);

	/* todo , refer the kXtGTPUInterInsert */
	if (NULL == cp || NULL == cp_up)
	{
		pr_err("gtpu: xt_gtpu_tab_down_modify failed, cp = %llx, cp_up = %llx\n", GTPU_PTR2UINT(cp), GTPU_PTR2UINT(cp_up));
		ret = -1; 
	}			
	ret = 0;

	XT_GTPU_INTER_MODIFYCNT(ret);
	return ret;
}

//delete a user-info to xt_GTPU_tab
static int xt_gtpu_inter_delete(struct xt_gtpu_tab_down_param *p, struct xt_gtpu_tab_up_param *p_up)
{
	struct xt_gtpu_tab_down_t* cp = NULL;
	struct xt_gtpu_tab_up_t* cp_up = NULL;
	int ret = -1;
	
	cp = __xt_gtpu_tab_down_in_get(p);
	cp_up = __xt_gtpu_tab_up_in_get(p_up);
	if (NULL != cp)
	{
		xt_gtpu_tab_down_delete(cp);
		ret = 0;
	}
	if (NULL != cp_up)
	{
		xt_gtpu_tab_up_delete(cp_up);
		ret = 0;
	}

	XT_GTPU_INTER_DELETECNT(ret);
	return ret;
}

//xt_gtpu_inter_test_search() is for testing insert/modify/delete
static int xt_gtpu_inter_test_search(struct xt_gtpu_tab_down_param *p, struct xt_gtpu_tab_up_param *p_up)
{
	struct xt_gtpu_tab_down_t* cp = NULL;
	struct xt_gtpu_tab_up_t* cp_up = NULL;
	int ret = -1;
	
	cp = __xt_gtpu_tab_down_in_get(p);
	cp_up = __xt_gtpu_tab_up_in_get(p_up);
	
	if (NULL == cp || NULL == cp_up)
	{
		pr_err("gtpu: kXtGTPUInterTestSearchInsert failed\n");
		return ret;
	}
	if (cp->enodeBip == p->enodeBip &&
		cp->UEip == p->UEip &&
		cp->enodeteid == p->enodeteid &&
		cp->GWteid == p->GWteid &&
		cp->enodeBport == p->enodeBport &&
		cp_up->enodeBip == p_up->enodeBip &&
		cp_up->UEip == p_up->UEip &&
		cp_up->GWteid == p_up->GWteid &&
		cp_up->enodeBport == p_up->enodeBport)
	{
		ret = 0;
	}

	return ret;
}

//reset error stats
static int xt_gtpu_inter_reset_errorstats(struct xt_gtpu_t *xt_gtpu)
{
	struct xt_gtpu_error_info_stats *errinfo;

	errinfo = &(xt_gtpu->tot_stats.errinfo);
	
	atomic_set(&(errinfo->GTPUerror_cnt), 0);
	atomic_set(&(errinfo->GTPUeNB_cnt), 0);
	atomic_set(&(errinfo->insert_fail_cnt), 0);
	atomic_set(&(errinfo->modify_fail_cnt), 0);
	atomic_set(&(errinfo->delete_fail_cnt), 0);

	return 0;
}

//reset cpu-value stats
static int xt_gtpu_inter_reset_cpustats(struct xt_gtpu_t *xt_gtpu, 
															struct xt_gtpu_cpu_stats __percpu *per_cpu_stats)
{
	int i;
	
	for_each_possible_cpu(i) {
		struct xt_gtpu_cpu_stats *stats = per_cpu_ptr(per_cpu_stats, i);
		stats->ustats.erruppkts = 0;
		stats->ustats.errdownpkts = 0;
		stats->ustats.alluppkts = 0;
		stats->ustats.alldownpkts = 0;
		stats->ustats.uppkts = 0;
		stats->ustats.downpkts = 0;
		stats->ustats.upbytes = 0;
		stats->ustats.downbytes = 0;

		stats->ustats.insert_success_num = 0;
		stats->ustats.modify_success_num = 0;
		stats->ustats.delete_success_num = 0;
	}

	return 0;
}

static int xt_gtpu_inter_reset_allstats(struct xt_gtpu_t *xt_gtpu)
{
	
	xt_gtpu_inter_reset_errorstats(xt_gtpu);
	xt_gtpu_inter_reset_cpustats(xt_gtpu, (xt_gtpu->tot_stats.cpustats));
	
	return 0;
}

static int xt_gtpu_inter_get_errorstats(struct xt_gtpu_t *xt_gtpu, struct xt_gtpu_inter_msg_errorinfo_stats *msg)
{
	struct xt_gtpu_error_info_stats *errinfo;

	msg->msgtype = kXtGTPUInterGetErrorStatsInfo;
	/* get atomic_t type error stats */
	errinfo = &(xt_gtpu->tot_stats.errinfo);
	msg->GTPUerror_pkts = atomic_read(&(errinfo->GTPUerror_cnt));
	msg->GTPUeNB_pkts = atomic_read(&(errinfo->GTPUeNB_cnt));
	msg->insert_fail_num = atomic_read(&(errinfo->insert_fail_cnt));
	msg->modify_fail_num = atomic_read(&(errinfo->modify_fail_cnt));
	msg->delete_fail_num = atomic_read(&(errinfo->delete_fail_cnt));

	/* get cpu stats stats */
	//xt_gtpu->tot_stats
	xt_gtpu_read_cpu_error_stats(msg, (xt_gtpu->tot_stats.cpustats));
	
	return 0;
}

static int xt_gtpu_inter_print_errorstats(struct xt_gtpu_t *xt_gtpu, struct xt_gtpu_inter_msg_errorinfo_stats *msg)
{
	pr_info("gtpu: GTPUerror_pkts = %d\n", msg->GTPUerror_pkts);
	pr_info("gtpu: GTPUeNB_pkts = %d\n", msg->GTPUeNB_pkts);
	
	pr_info("gtpu: insert_success_num = %d\n", msg->insert_success_num);
	pr_info("gtpu: insert_fail_num = %d\n", msg->insert_fail_num);
	pr_info("gtpu: modify_success_num = %d\n", msg->modify_success_num);
	pr_info("gtpu: modify_fail_num = %d\n", msg->modify_fail_num);
	pr_info("gtpu: delete_success_num = %d\n", msg->delete_success_num);
	pr_info("gtpu: delete_fail_num = %d\n", msg->delete_fail_num);

	return 1;
}

/* decode the message */
static int 
_gtpu_kernel_receive_dec(char *msg)
{
	struct xt_gtpu_inter_msg *decmsg = NULL;
	struct xt_gtpu_tab_down_param p;
	struct xt_gtpu_tab_up_param p_up;
	int ret;
	/* only used in case kXtGTPUInterGetStats and kXtGTPUInterPrintErrorStats*/
	struct xt_gtpu_inter_msg_errorinfo_stats error_info_msg;
	
	if (NULL == msg)
	{
		return -1;
	}
		
	decmsg = (struct xt_gtpu_inter_msg *)msg;
	xt_gtpu_tab_down_fill_param(decmsg->UEip, decmsg->enodeBip, decmsg->enodeteid, decmsg->GWteid, decmsg->enodeBport, &p);
	xt_gtpu_tab_up_fill_param(decmsg->UEip, decmsg->enodeBip, decmsg->GWteid, decmsg->enodeBport, &p_up);
	
	switch(decmsg->msgtype)
	{
		case kXtGTPUInterInsert:
			/* rebuild */
			ret = xt_gtpu_inter_insert(&p, &p_up);
			break;
		case kXtGTPUInterModify:
			ret = xt_gtpu_inter_modify(&p, &p_up);
			break;
		case kXtGTPUInterDelete:
			ret = xt_gtpu_inter_delete(&p, &p_up);
			break;
		case kXtGTPUInterSetVirtIP:
			/* UEip in decmsg is used to transmit the virtual IP */
			xt_gtpu_inter_set_virtual_IP(decmsg->UEip);
			ret = 0;
			break;
		case kXtGTPUInterTestSearchInsert:
			ret = xt_gtpu_inter_test_search(&p, &p_up);
			break;
		case kXtGTPUInterResetAllStats:
			ret = xt_gtpu_inter_reset_allstats(&g_xt_GTPU_stats);
			break;
		case kXtGTPUInterResetErrorStats:
			ret = xt_gtpu_inter_reset_errorstats(&g_xt_GTPU_stats);
			break;
		case kXtGTPUInterGetErrorStats:
			//xt_gtpu_send_statsmsg
			xt_gtpu_inter_get_errorstats(&g_xt_GTPU_stats, &error_info_msg);
			ret = xt_gtpu_send_statsmsg((char *)&error_info_msg, sizeof(struct xt_gtpu_inter_msg_errorinfo_stats));
			break;
		case kXtGTPUInterPrintErrorStats:
			xt_gtpu_inter_get_errorstats(&g_xt_GTPU_stats, &error_info_msg);
			// struct xt_gtpu_inter_msg_stats_all is hard to get , so don't print it info.
			ret = xt_gtpu_inter_print_errorstats(&g_xt_GTPU_stats, &error_info_msg);
		default:
			/* not matched msgtype */
			ret = -1;
			goto _gtpu_kernel_receive_dec_return;
			break;
	}

_gtpu_kernel_receive_dec_return:
	return ret;
}

static int 
_gtpu_send_to_user(char *info, int datalen) //发送到用户空间
{
	int size;
	struct sk_buff *skb;
	unsigned int old_tail;
	struct nlmsghdr *nlh; //报文头

	int retval;

	size = NLMSG_SPACE(datalen+20); //报文大小
	skb = alloc_skb(size, GFP_KERNEL); //分配一个新的套接字缓存,使用GFP_ATOMIC标志进程不>会被置为睡眠
	if (skb == NULL)
	{
		pr_info("gtpu: alloc_skb Error\n");
	}
	//初始化一个netlink消息首部
	nlh = nlmsg_put(skb, 0, 0, 0, size, 0); 
	old_tail = skb->tail;
	
	//if the code below was deleted, the kernel will curshed. dont know why
	nlh->nlmsg_len = (skb->tail - old_tail); //设置消息长度
	
	//设置控制字段
	NETLINK_CB(skb).portid = 0;
	NETLINK_CB(skb).dst_group = 0;

	memcpy(NLMSG_DATA(nlh), info, datalen);
	//发送数据
	retval = netlink_unicast(netlinkfd, skb, g_user_process.pid, MSG_DONTWAIT);

	return 0;
}

static void
xt_gtpu_tab_fill_2user_msg_suc(struct xt_gtpu_inter_msg * decmsg, struct xt_gtpu_inter_msg *sendmsg)
{
	sendmsg->UEip = decmsg->UEip;
	sendmsg->enodeBip = decmsg->enodeBip;
	sendmsg->enodeteid = decmsg->enodeteid;
	sendmsg->GWteid = decmsg->GWteid;
	sendmsg->enodeBport = decmsg->enodeBport;
	
	switch (decmsg->msgtype)
	{
		case kXtGTPUInterInsert:
			sendmsg->msgtype = kXtGTPUInterInsertSuccess;
			return;
		case kXtGTPUInterModify:
			sendmsg->msgtype = kXtGTPUInterModifySuccess;
			return;
		case kXtGTPUInterDelete:
			sendmsg->msgtype = kXtGTPUInterDeleteSuccess;
			return;
		case kXtGTPUInterTestSearchInsert:
			sendmsg->msgtype = kXtGTPUInterTestSearchInsertSuccess;
			return;
		default:
			return;
	}
}

static void
xt_gtpu_tab_fill_2user_msg_fail(struct xt_gtpu_inter_msg * decmsg, struct xt_gtpu_inter_msg *sendmsg)
{
	sendmsg->UEip = decmsg->UEip;
	sendmsg->enodeBip = decmsg->enodeBip;
	sendmsg->enodeteid = decmsg->enodeteid;
	sendmsg->GWteid = decmsg->GWteid;
	sendmsg->enodeBport = decmsg->enodeBport;
	
	switch (decmsg->msgtype)
	{
		case kXtGTPUInterInsert:
			sendmsg->msgtype = kXtGTPUInterInsertFailed;
			return;
		case kXtGTPUInterModify:
			sendmsg->msgtype = kXtGTPUInterModifyFailed;
			return;
		case kXtGTPUInterDelete:
			sendmsg->msgtype = kXtGTPUInterDeleteFailed;
			return;
		case kXtGTPUInterTestSearchInsert:
			sendmsg->msgtype = kXtGTPUInterTestSearchInsertFailed;
			return;
		default:
			return;
	}
}

/* not used now */
static int 
_gtpu_kernel_send_dec(int ret, char *msg)
{
	int sendret;
	struct xt_gtpu_inter_msg p;
	struct xt_gtpu_inter_msg *decmsg = (struct xt_gtpu_inter_msg *)msg;

	switch (ret)
	{
		case GTPU_SUCCESS_SEND:
			xt_gtpu_tab_fill_2user_msg_suc(decmsg, &p);
			sendret = _gtpu_send_to_user((char *)&p, sizeof(struct xt_gtpu_inter_msg));
			break;
		case GTPU_FAILURE_SEND:
			xt_gtpu_tab_fill_2user_msg_fail(decmsg, &p);
			sendret = _gtpu_send_to_user((char *)&p, sizeof(struct xt_gtpu_inter_msg));
			break;
			
		case GTPU_INFO_SEND:
			sendret = _gtpu_send_to_user((char *)&p, sizeof(struct xt_gtpu_inter_msg));
			pr_err("gtpu: _gtpu_kernel_send_dec receive GTPU_INFO\n");
			//todo
			break;
		default:
			pr_err("gtpu: _gtpu_kernel_send_dec unknown ret val\n");	
			sendret = -1;
			goto _gtpu_kernel_send_dec_return;
	}
	
_gtpu_kernel_send_dec_return:
	return sendret;
}

/*
	receive msg from user space
*/
static void 
_gtpu_kernel_receive(struct sk_buff *__skb) 
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh = NULL;
	int ret;
	char *data;
	
	skb = skb_get(__skb);

	if(skb->len >= sizeof(struct nlmsghdr)){
		nlh = (struct nlmsghdr *)skb->data;
		if((nlh->nlmsg_len >= sizeof(struct nlmsghdr))
		&& (__skb->len >= nlh->nlmsg_len))
		{
			g_user_process.pid = nlh->nlmsg_pid;
			//get data ptr
			data = (char *)NLMSG_DATA(nlh);

			ret = _gtpu_kernel_receive_dec(data);
#ifdef LH_TEST_CASE_HASHTAB			
			_gtpu_kernel_send_dec(ret, data);
			//todo
#endif
		}
	}
	/* msg doesn't have nlmsghdr */
	else
	{
		printk(KERN_DEBUG "[kernel space] data receive from user are:%s\n",(char *)NLMSG_DATA(nlmsg_hdr(__skb)));
	}

	kfree_skb(skb);
}

#if 0
//todo 
static int 
_gtpu_target_down_notFound(unsigned int UEip)
{
	struct xt_gtpu_inter_msg p;
	int ret;
	
	p.msgtype = kXtGTPUDownPacketNotFound;
	p.UEip = UEip;

	ret = _gtpu_kernel_send_dec(GTPU_INFO_SEND, (char *)&p);
	if (ret == -1)
	{
		pr_err("gtpu: _gtpu_target_notFound _gtpu_kernel_send_dec failed\n");
	}

	return ret;
}

static int 
_gtpu_target_up_notFound(unsigned int GWteid)
{
	int ret = 0;

	return ret;
}
#endif

static int 
_gtpu_route_packet(struct net *net, struct sk_buff *skb, const struct xt_gtpu_target_info *info) 
{
    int err = -1;
	int err_eval = - 1;
    struct rtable *rt = NULL; 
    struct iphdr *iph = ip_hdr(skb); 
	struct flowi4 fl4;
	static int pr_cnt = 0;
	static int pr_cnt_send = 0;
	
	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = iph->daddr;
	fl4.flowi4_flags = FLOWI_FLAG_KNOWN_NH;

    /* Get the route using the standard routing table. */ 
	rt = ip_route_output_key(&init_net, &fl4);
	
    if (unlikely(IS_ERR(rt))) 
    {
    	pr_cnt++;
		if (pr_cnt%1024 == 0)
		{
        	pr_info("GTPU: Failed to route packet to dst 0x%x. PTR_ERR(rt) = %lx", fl4.daddr, PTR_ERR(rt)); 
		}
		
		kfree_skb(skb);
		skb = NULL;
		
        return GTPU_FAILURE; 
    } 
	
    skb_dst_drop(skb);
	/*
	Sets skb dst, assuming a reference was taken on dst and should be released by skb_dst_drop()
	*/
    skb_dst_set(skb, &rt->dst);
	
    skb->dev      = skb_dst(skb)->dev;
    skb->protocol = htons(ETH_P_IP); 

    /* Send the GTPu message out...gggH */
    //err = dst_output(skb);
	err = ip_local_out(skb);
	err_eval = net_xmit_eval(err);
	
#ifdef LH_DO_GETTIMEOFDAY
	int time_val;

	struct timeval time_val;
	do_gettimeofday(&time_val);
	pr_info("GTPU: time is %d\n", (time_val.tv_sec - time_val.tv_sec) * 1000000 + (time_val.tv_usec - time_val.tv_usec));
#endif

	if (likely(err_eval == 0))
	{
		return GTPU_SUCCESS;
	}
	else
	{
		pr_cnt_send++;
		if (pr_cnt_send%1024 == 0)
		{
			pr_info("gtpu: ip_local_out failed!, err = %x\n", err); 
		}
		
		return GTPU_FAILURE;
	}
}

static unsigned int
_gtpu_target_add(struct sk_buff *skb, const struct xt_gtpu_target_info *tgi)
{
    struct iphdr *iph = ip_hdr(skb);
	struct iphdr *gtpu_iph = NULL;
    struct udphdr *udph = NULL;
    struct gtpuhdr *gtpuh = NULL;
    struct sk_buff *new_skb = NULL;
    int headroom_reqd =  sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtpuhdr);
    int orig_iplen = 0, udp_len = 0, ip_len = 0;
	struct xt_gtpu_tab_down_param p;
	struct xt_gtpu_tab_down_t *cp;
	int ret = 0;

	/* stats all the pkts */
	xt_gtpu_down_stats_all(&g_xt_GTPU_stats, skb);
	///* to do, tgi need to be replaced */

    /* Keep the length of the source IP packet */
    orig_iplen = ntohs(iph->tot_len);

	/* search the GTPU packet hdr info */
	xt_gtpu_tab_down_fill_param(iph->daddr, 0, 0, 0, 0, &p);
	cp = __xt_gtpu_tab_down_in_get(&p);
	if (unlikely(cp == NULL))
	{
		pr_info("gtpu: unknown UEip, packet need to packet. UEip is %x\n", iph->daddr);
		/* need to save the packet. */
	//	ret = _gtpu_target_down_notFound(iph->daddr);
		if (ret == 0)
			return NF_DROP;
		else
			return NF_DROP;
	}
	
    /* Create a new copy of the original skb...can't avoid :-( */
    new_skb = skb_copy_expand(skb, headroom_reqd + skb_headroom(skb), skb_tailroom(skb), GFP_ATOMIC);
    if (unlikely(new_skb == NULL))
    {
        return NF_DROP;
    }

    /* Add GTPu header */
    gtpuh = (struct gtpuhdr*)skb_push(new_skb, sizeof(struct gtpuhdr));
    gtpuh->flags = 0x30; /* v1 and Protocol-type=GTP */
    gtpuh->msgtype = 0xff; /* T-PDU */
    gtpuh->length = htons(orig_iplen);
    gtpuh->tunid = htonl(cp->enodeteid);

    /* Add UDP header */
    udp_len = sizeof(struct udphdr) + sizeof(struct gtpuhdr) + orig_iplen;
    udph = (struct udphdr*)skb_push(new_skb, sizeof(struct udphdr));
    udph->source = htons(GTPU_PORT);
    udph->dest = (cp->enodeBport);
    udph->len = htons(udp_len);
    udph->check = 0;
    udph->check = csum_tcpudp_magic(g_xt_GTPU_kernel_virtual_IP, cp->enodeBip, udp_len, IPPROTO_UDP, csum_partial((char*)udph, udp_len, 0));
    skb_set_transport_header(new_skb, 0);

    /* Add IP header */
    ip_len = udp_len + sizeof(struct iphdr);
    gtpu_iph = (struct iphdr*)skb_push(new_skb, sizeof(struct iphdr));
    gtpu_iph->ihl      = 5;
    gtpu_iph->version  = 4;
    gtpu_iph->tos      = 0;
    gtpu_iph->tot_len  = htons(ip_len);
    gtpu_iph->id       = 0;
    gtpu_iph->frag_off = 0;
    gtpu_iph->ttl      = 64;
    gtpu_iph->protocol = IPPROTO_UDP;
    gtpu_iph->check    = 0;
    gtpu_iph->saddr    = (g_xt_GTPU_kernel_virtual_IP);//self ip?
    gtpu_iph->daddr    = (cp->enodeBip);
    gtpu_iph->check    = ip_fast_csum((unsigned char *)gtpu_iph, gtpu_iph->ihl);
    skb_set_network_header(new_skb, 0);

    /* Route the packet */
	ret = _gtpu_route_packet(&init_net, new_skb, tgi);

    if (likely(ret == GTPU_SUCCESS))
    {
        /* Succeeded. Drop the original packet */
		xt_gtpu_down_stats(&g_xt_GTPU_stats, new_skb);
        return NF_DROP;
    }
    else
    {
    	xt_gtpu_down_stats_err(&g_xt_GTPU_stats, skb);
    //    kfree_skb(new_skb);//should not here, for dst_out had already free the skb
        return NF_DROP; /* What should we do here ??? ACCEPT seems to be the best option */
    }
}

/*
#define GTPU_PKT_TPU_TYPE 0xff
#define GTPU_PKT_ERRINDICATION_TYPE 0x1a

*/
static int
xt_gtpu_judge_GTPUtype(uint8_t pkt_type)
{
	int ret;
	switch(pkt_type)
	{
		case GTPU_PKT_TPU_TYPE:
			return 0;
		case GTPU_PKT_ERRINDICATION_TYPE:
			//stats the ErrorIndication
			return -1;
		default:
			return -1;
	}
}

//xt_gtpu_up_stats_all
//xt_gtpu_up_stats_err
static unsigned int
_gtpu_target_rem(struct sk_buff *orig_skb, const struct xt_gtpu_target_info *tgi)
{	
    struct iphdr *iph = ip_hdr(orig_skb);
	struct iphdr *iph_new = NULL;
    struct gtpuhdr *gtpuh = NULL;
    struct sk_buff *skb = NULL;
	struct net * net = xt_gtpu_skb_net(orig_skb);
	unsigned int GWteid;
	struct xt_gtpu_tab_up_param p;
	struct xt_gtpu_tab_up_t *cp;
	int ret;
	uint8_t gtpu_pkt_type;
	
	/* stats all the pkts */
	xt_gtpu_up_stats_all(&g_xt_GTPU_stats, skb);
	
    /* Create a new copy of the original skb...can't avoid :-( */
    skb = skb_copy(orig_skb, GFP_ATOMIC);
    if (unlikely(skb == NULL))
    {
        return NF_DROP;
    }

	/* judge the packet is the GTPU data pkt*/
	gtpu_pkt_type = xt_gtpu_get_GTPUtype(orig_skb);
	ret = xt_gtpu_judge_GTPUtype(gtpu_pkt_type);
	if (ret == -1)
	{
		return NF_DROP;
	}
	
	/* judge the packet is the GTPU pkt or validate pkt */
	GWteid = xt_gtpu_get_GTPUteid(orig_skb);
	xt_gtpu_tab_up_fill_param(0, 0, GWteid, 0, &p);
	cp = __xt_gtpu_tab_up_in_get(&p);
	if (unlikely(cp == NULL))
	{
		pr_err("gtpu: pkt GWteid unknown. pkt GWteid is %x\n", GWteid);
		return NF_DROP;
	}
	
    /* Remove IP header */
    skb_pull(skb, (iph->ihl << 2));
	//unlikely skb_pull return NULL
	
    /* Remove UDP header */
    gtpuh = (struct gtpuhdr*)skb_pull(skb, sizeof(struct udphdr));

    /* Remove GTPu header */
    skb_pull(skb, sizeof(struct gtpuhdr));

    /* If additional fields are present in header, remove them also */
    if (unlikely(gtpuh->flags & GTPU_ANY_EXT_HDR_BIT))
    {
    	printk(KERN_ALERT "skb_pull(skb, sizeof(short) + sizeof(char) + sizeof(char));\n");
        skb_pull(skb, sizeof(short) + sizeof(char) + sizeof(char)); /* #Seq, #N-PDU, #ExtHdr Type */
    }
	/* set Layer Header */
    skb_set_network_header(skb, 0);
    skb_set_transport_header(skb, 0);

	/* cal the IP checksum */
	iph_new = ip_hdr(skb);
	iph_new->check = 0;
	iph_new->check = ip_fast_csum((unsigned char *)iph_new, iph_new->ihl);
	
    /* Route the packet */
    ret = _gtpu_route_packet(net, skb, tgi);
	if (likely(ret == GTPU_SUCCESS))
	{
		xt_gtpu_up_stats(&g_xt_GTPU_stats, skb);
		return NF_DROP;
	}
	else
    {
    	xt_gtpu_up_stats_err(&g_xt_GTPU_stats, skb);
        return NF_DROP; /* What should we do here ??? ACCEPT seems to be the best option */
    }
}

static unsigned int
xt_gtpu_target(struct sk_buff *skb, const struct xt_action_param *par)
{
    const struct xt_gtpu_target_info *tgi = par->targinfo;
    int result = NF_ACCEPT;

    if (unlikely(tgi == NULL))
    {
        return result;
    }

    if (tgi->action == PARAM_GTPU_ACTION_ADD)
    {
        result = _gtpu_target_add(skb, tgi);
    }
    else if (tgi->action == PARAM_GTPU_ACTION_REM)
    {
        result = _gtpu_target_rem(skb, tgi);
    }
    else if (tgi->action == PARAM_GTPU_ACTION_TRANSPORT)
    {
    }

    return result;
}

//_gtpu_send_to_user
//send stats msg
unsigned int 
xt_gtpu_send_statsmsg(char *statsMsg, unsigned int msg_len)
{
	_gtpu_send_to_user(statsMsg, msg_len);

	return 0;
}

static struct xt_target xt_gtpu_reg __read_mostly = 
{
    .name           = "GTPU",
    .family         = AF_INET,
    .table          = "mangle",
    .target         = xt_gtpu_target,
    .targetsize     = sizeof(struct xt_gtpu_target_info),
    .me             = THIS_MODULE,
};

static void __exit xt_gtpu_netlink_cleanup(void)
{
	sock_release(netlinkfd->sk_socket);
}

static int __init xt_gtpu_init(void)
{
	int ret;
	struct netlink_kernel_cfg cfg = {
		.input = _gtpu_kernel_receive,
	};
	
    pr_info("GTPU: Initializing module (KVersion: %d)\n", 1);
    pr_info("GTPU: Copyright Polaris Networks 2015-2016\n");
	pr_info("GTPU: version 0.9.5.1\n");

	/* must be set then this ip can be used */
	g_xt_GTPU_kernel_virtual_IP = 0;
	
	ret = xt_gtpu_tab_down_init();
	if (ret < 0) {
		pr_err("can't setup xt_gtpu_down table.\n");
		goto cleanup_protocol;
	}

	ret = xt_gtpu_tab_up_init();
	if (ret < 0)
	{
		pr_err("can't setup xt_gtpu_up table.\n");
		goto cleanup_xt_gtpu_down;
	}
	
	netlinkfd = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if(!netlinkfd){
        pr_err("can not create a netlink socket\n");
        ret = -1;
        goto cleanup_netlink;
    }

	ret = xt_register_target(&xt_gtpu_reg);
	if (ret < 0)
	{
		pr_err("can't register target xt_gtpu_reg.\n");
		goto cleanup_gtpu_target;
	}

	ret = xt_gtpu_estimator_init(&g_xt_GTPU_stats);
	if (ret < 0)
	{
		pr_err("can't init the xt_gtpu estimator and timer.!\n");
		goto cleanup_gtpu_estimator;
	}
    return ret;
	
cleanup_gtpu_estimator:
	xt_unregister_target(&xt_gtpu_reg);
cleanup_gtpu_target:
	xt_gtpu_netlink_cleanup();
cleanup_netlink:
	xt_gtpu_tab_up_cleanup();
cleanup_xt_gtpu_down:
	xt_gtpu_tab_down_cleanup();
cleanup_protocol:
	return ret;

}

static void __exit xt_gtpu_exit(void)
{
	xt_gtpu_estimator_cleanup(&g_xt_GTPU_stats);
	
    xt_unregister_target(&xt_gtpu_reg);
    pr_info("GTPU: Unloading module\n");

	xt_gtpu_netlink_cleanup();
    pr_info("test_netlink_exit!!\n");
	xt_gtpu_tab_up_cleanup();
	xt_gtpu_tab_down_cleanup();
}

module_init(xt_gtpu_init);
module_exit(xt_gtpu_exit);

