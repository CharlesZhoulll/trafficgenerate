/*
 * tcptuning - Observe the TCP flow with kprobes.
 *
 * The idea for this came from Werner Almesberger's umlsim
 * Copyright (C) 2004, Stephen Hemminger <shemminger@osdl.org>
 * Copyright (C) 2013, Timo Dörr <timo@latecrew.de> (minor fixes and
 *  changes)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/hashtable.h>
#include <linux/circ_buf.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <linux/kmod.h>
// For debuging
#include <linux/sched.h>
#include <linux/delay.h>
//#include "tcp_cubic.h"

MODULE_AUTHOR("Fan Zhou <zhou.fan1@husky.neu.edu>");
MODULE_DESCRIPTION("TCP adapt system");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.1");

/* maximum amount of probes to be buffered before forced-outpvoid mdelay(ut
 * to userspace
 */

#define INFINITY_U32 0xffffffff
#define True 1
#define False 0
#define TCP_CUBIC 1
#define TCP_VEGAS 2
#define TCP_UNCERTAIN 0
#define VEGAS_BETA 4
#define ALPHA_SCALE 10 // 16, just test
#define ALPHA 2
#define TCP_CA_Open 0
#define TCP_CA_Disorder 1
#define TCP_CA_CWR 2
#define TCP_CA_Recovery 3
#define TCP_CA_Loss 4
#define LEVEL_1 1
#define LEVEL_2 2

static u16 bufsize = 4096;
static int act = 1;
static char *config = 0;
static char *procname = "janus";

module_param(act, int, 0);
MODULE_PARM_DESC(open, "1=enable tcptuning,  otherwise");
MODULE_PARM_DESC(config, "Config port and target rate");
module_param(config, charp, 0);
module_param(procname, charp, 0);
MODULE_PARM_DESC(procname, "Default proc name, also root name of trace file");

DEFINE_HASHTABLE(socket_htable, 16);

struct tcp_log {
    ktime_t conn_start;
	__be32 saddr, daddr;
	__be16 sport, dport;
	u16 length;
	u32 snd_nxt;
	u32 snd_una;
	u32 snd_wnd;
	u32 snd_cwnd;
	u32 ssthresh;
	u8 tcp_state;
	u32 rtt;  // moving average of rtt
	u32 rtt_min_pre;
	u32 rtt_avg;
	u32 est_pdelay;
	u32 epo_rtt_min;
	u32 tp_avg; // moving average of tp_smp
	u32 tp_smp;
	u32 temp_rate; // average tp in one window
	u8 rtt_stable;
	u32 inverse_slope;
	u32 inverse_ssh;
};

struct socket_hlist_item {
     struct pre_config *cfg;
     struct hlist_node next;
} ;

struct janus {
     struct socket_info *sk_info;
} ;

struct pre_config {
	u32 sport;
	u32 rate;
};

struct socket_info {
	// For system states
	ktime_t conn_start;   // When does flow just start
	u32 rate;
	u32 temp_rate;
	u32 temp_rate_cache;  // cached temp rate when the network is converge
	u8 	reduce_scale; // For reduce temp rate
	u8 cur_tcp;  // CUBIC 0, VEGAS 1
	u32 sport;
	u32 dport;
	u32 clamp_state;	// True: in clamp, False: disable clamp
	u32 clamp_value;
	u32 ssthresh;	// slow start ssthresh
	u32 last_rate_reduce_ts;	// last time stamp when reducing target rate
	u32 rate_reduce_inv;   // rate reduce interval
	u8 compete;
	u8 in_slow_start;
	u32 pkt_recover_ts;

	// For TCP state
	u8 tcp_state;
	u8 last_tcp_state;

	// For tp
	u32 total_byte_win; // total byte sent in one window
	u32 est_tp;   // estimate throughput
	u32 est_tp_smp;  // sampled throughput
	u8 tp_do_smp;	 // Just start up, do not take moving average
	u32 last_una;  // last un-acked seq, used in throughput estimation
	u32 last_una_ts; // last time stamp when receive ack, used in throughput estimation
	u32 tp_left_ts;  // left end of time window
	u32 accounted;  // duplicate acked segments

	// For RTT
	u32 est_pdelay;	 // Estimate round trip propagation delay
	u32 epo_rtt_min; // min_rtt in every switching cycle
	u32 rtt;	// RTT copied from the linux kernel
	u32 rtt_avg;	// Moving averaged RTT
	u32 rtt_min_pre; // Min filtered RTT in this RTT
	u32 rtt_min_this; // The minimum RTT in previous RTT, using this RTT as actuall min filtered RTT
	u32 rtt_left_ts; // Left window of taking min filtered RTT
	u32 last_rate_reduce_rtt;  // last RTT when reducing temp rate

	// For slope
	u32 slope_start_ts; // time stamp of start taking rtt samples
	u32 sam_num; // Number of sample points take
	u32 sum_x; // sum(x)
	u32 sum_y;  // sum(y)
	u32 sumsq_xx; // sum(x^2)
	u32 sumsq_xy; // sum(xy)
	u8 rtt_stable;  // whether rtt has been stable
	u32 inverse_slope; // The inverse of slope, not sure of whether used or not
	u32 inverse_ssh;  // The inverse of ssh to check whether RTT has been stable..not sure of whether used
};

static struct {
    spinlock_t producer_lock, consumer_lock;
    wait_queue_head_t wait;
    ktime_t janus_start;
    unsigned long head, tail;
    struct tcp_log *log;
    u32 lastcwnd;
}tcp_info;

static inline u32 filter(u32 avg, u32 smp)
{
    u32 k = ((7 * avg) + smp) >> 3;
    return k;
}

// For estimating throughput, taken from tcp westwood.c
static inline u32 count_ack(struct sock *sk, struct socket_info *sk_info)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    u32 cumul_ack = tp->snd_una - sk_info->last_una;

    /* If cumul_ack is 0 this is a dupack since it's not moving
     * tp->snd_una.
     */
    if (!cumul_ack) {
        sk_info->accounted += tp->mss_cache;
        cumul_ack = tp->mss_cache;
    }

    if (cumul_ack > tp->mss_cache) {
        /* Partial or delayed ack */
        if (sk_info->accounted >= cumul_ack) {
            sk_info->accounted -= cumul_ack;
            cumul_ack = tp->mss_cache;
        } else {
            cumul_ack -= sk_info->accounted;
            sk_info->accounted = 0;
        }
    }
    sk_info->last_una = tp->snd_una;

    return cumul_ack;
}

static void estimate_tp(struct sock *sk, struct socket_info *sk_info)
{
	// Fix: does it really needed to multiple this by 1000 and delete it later ??
	struct timespec tv = ktime_to_timespec(
			ktime_sub(ktime_get(), tcp_info.janus_start));
	const struct tcp_sock *tp = tcp_sk(sk);
	s32 delta = tcp_time_stamp - sk_info->tp_left_ts;  // in ms
	sk_info->total_byte_win += count_ack(sk, sk_info);
	if (delta > sk_info->rtt) {
		// If we have got at least 1/8*cwnd's samples
		u32 bytes_th = (tp->snd_cwnd >> 3) * tp->mss_cache;
		if (sk_info->total_byte_win >= bytes_th && (delta <= 2*sk_info->rtt)) {
			u32 tp_smp = sk_info->total_byte_win * HZ / delta;  // in byte/s
			sk_info->est_tp_smp = tp_smp;
			if (!sk_info->est_tp) {
				sk_info->est_tp = tp_smp;
				sk_info->tp_do_smp = True;
			} else {
				if (sk_info->tp_do_smp)
					sk_info->est_tp = tp_smp;
				else
					sk_info->est_tp = filter(sk_info->est_tp, tp_smp);
			}
		}
		sk_info->total_byte_win = 0;
		sk_info->tp_left_ts = tcp_time_stamp;
	}
}

static inline void estimate_rtt(struct sock *sk, struct socket_info *sk_info)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	// In jiffy
	sk_info->rtt = usecs_to_jiffies(tp->srtt_us >> 3); // Transfer that into jiffer
	sk_info->rtt_avg = filter(sk_info->rtt_avg, sk_info->rtt);
	if ((!sk_info->epo_rtt_min)) {
		// Be cautious about min_rtt setting
		sk_info->est_pdelay = sk_info->rtt;
		sk_info->epo_rtt_min = sk_info->rtt;
		sk_info->rtt_min_this = sk_info->rtt;
	} else {
		if (sk_info->rtt < sk_info->rtt_min_this)
			sk_info->rtt_min_this = sk_info->rtt;
		if (sk_info->rtt < sk_info->epo_rtt_min) {
			sk_info->epo_rtt_min = sk_info->rtt;
			sk_info->est_pdelay = sk_info->epo_rtt_min;
			// Update estimation of propogation delay (think more on this..)
			if (sk_info->est_tp && (sk_info->cur_tcp == TCP_VEGAS)
					&& (!sk_info->tp_do_smp)) {
				u32 qu_delay_idl = (VEGAS_BETA * HZ * tp->mss_cache)
						/ sk_info->est_tp;
				if (qu_delay_idl < sk_info->est_pdelay)
					sk_info->est_pdelay -= qu_delay_idl;
			}
		}
	}
	u32 delta = tcp_time_stamp - sk_info->rtt_left_ts;  // in HZ
	// Taken minimum filter of RTT in each RTT. rtt_min_pre is the minimum rtt sample in last rtt
	if (delta > sk_info->rtt) {
		sk_info->rtt_min_pre = sk_info->rtt_min_this;
		sk_info->rtt_min_this = sk_info->rtt;
		sk_info->rtt_left_ts = tcp_time_stamp;
	}
}

// Trend estimation
static inline void reset_slope_cal(struct socket_info *sk_info)
{
	sk_info->sum_x = 0;
	sk_info->sum_y = 0;
	sk_info->sumsq_xx = 0;
	sk_info->sumsq_xy = 0;
	sk_info->sam_num = 0;
	sk_info->slope_start_ts = 0;
}


static void estimate_trend(struct sock *sk, struct socket_info *sk_info)
{
	struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_info.janus_start));
	const struct tcp_sock *tp = tcp_sk(sk);
	if (sk_info->cur_tcp == TCP_VEGAS)
	{
		if (!sk_info->slope_start_ts) {
			sk_info->slope_start_ts = tcp_time_stamp;
		} else {
			u32 time_gap = tcp_time_stamp - sk_info->slope_start_ts;
			// Fix, parameter tuning
			if (time_gap < 10 * sk_info->rtt) {
				// I think you should consider scale it.
				u32 x = tcp_time_stamp - sk_info->slope_start_ts;
				// Using rtt_avg to compute slope
				u32 y = sk_info->rtt_avg;
				sk_info->sum_x += x;
				sk_info->sum_y += y;
				sk_info->sumsq_xx += x * x;
				sk_info->sumsq_xy += x * y;
				sk_info->sam_num++;
			} else {
				u32 temp = sk_info->sumsq_xy/sk_info->sum_x*sk_info->sam_num;
				// The reason for temp_refine is to take care of the floating point
				u32 temp_refine = (sk_info->sumsq_xy%sk_info->sum_x) << 4;
				temp_refine = temp_refine/sk_info->sum_x;
				temp_refine *= sk_info->sam_num;
				temp_refine >>= 4;
				temp += temp_refine;
				sk_info->rtt_stable = (temp <= sk_info->sum_y);


				// The rest are not so important, if you do not need fine grained analysis in
				// the slope

				s32 elem = temp - sk_info->sum_y;
				// elem requires further refining..
				u32 denom = sk_info->sumsq_xx/sk_info->sum_x*sk_info->sam_num - sk_info->sum_x;
				if (elem)
				{
					sk_info->inverse_slope = denom/abs(elem);
				}
				else
				{
					sk_info->inverse_slope = INFINITY_U32;
				}


				//sk_info->rtt_stable = sk_info->inverse_slope > sk_info->inverse_ssh;
				if (sk_info->rtt_stable)
				{
					if (sk_info->compete) {
						sk_info->compete = False;
					}
					//sk_info->temp_rate_cache = sk_info->temp_rate;
				}
/*				pr_info(
						"N:%u, sum_x:%u, sum_y:%u, sumsq_xy:%u sumsq_xx:%u  \n",
						sk_info->sam_num, sk_info->sum_x, sk_info->sum_y,
						sk_info->sumsq_xy, sk_info->sumsq_xx);
				pr_info("%lu.%09lu: %u denom: %u, elem: %d, inverse_slope: %u \n", (unsigned long) tv.tv_sec,
	                    (unsigned long) tv.tv_nsec, sk_info->sport, denom, elem, sk_info->inverse_slope);*/
				//pr_info("denom: %u, elem: %u, rtt: %u\n", denom, elem, sk_info->rtt);
				reset_slope_cal(sk_info);
			}
		}
	}
	else
	{
		sk_info->inverse_slope = 0;
		sk_info->rtt_stable = False;
		if (sk_info->slope_start_ts)
		{
			// Inverse slope should be 0, which means not stable
			// during cubic stage...
			reset_slope_cal(sk_info);
		}
	}
}

static inline char* get_tcp_name(int tcp)
{
    if (tcp == TCP_CUBIC)
        return "cubic";
    else if (tcp == TCP_VEGAS)
        return "vegas";
    else
        return "cubic";
}

static void switch_tcp_to(struct sock *sk, struct socket_info *sk_info, int tcp)
{
    int err;
    char *tcp_name = get_tcp_name(tcp);
    struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_info.janus_start));
    err = tcp_set_congestion_control(sk, tcp_name);
    if (!err)
    {
        pr_info("%lu.%09lu: %u->%u trying to modify TCP to %s, tp: %u, rtt: %u \n", (unsigned long) tv.tv_sec,
                (unsigned long) tv.tv_nsec, sk_info->sport, sk_info->dport, tcp_name,
                sk_info->est_tp, sk_info->rtt);
        sk_info->cur_tcp = tcp;
    }
    else
    {
        pr_info("%lu.%09lu: %u->%u fail to modify TCP to %s, tp: %u \n", (unsigned long) tv.tv_sec,
                (unsigned long) tv.tv_nsec, sk_info->sport, sk_info->dport, tcp_name,
                sk_info->est_tp);
    }
}

static void estimate_state(struct sock *sk, struct socket_info *sk_info)
{
	struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_info.janus_start));
    const struct inet_connection_sock *icsk = inet_csk(sk);
    // Get state
    sk_info->last_tcp_state = sk_info->tcp_state;
    sk_info->tcp_state = icsk->icsk_ca_state;
/*    // If now the tcp is not in TCP_CA_Open state, then it means that there is a packet loss event
    if (sk_info->tcp_state)
    {
    	sk_info->pkt_recover_ts = tcp_time_stamp;
    	return;
    }
    else
    {
    	if (sk_info->pkt_recover_ts)
    	{
    		// If it has been one RTT since the lost pkt has been recovered
    		if ((tcp_time_stamp - sk_info->pkt_recover_ts) < sk_info->rtt)
    			return;
    		sk_info->pkt_recover_ts = 0;
    		// If never get into 2nd level of competing mode, increase cwnd exponentially
    		// otherwise increase it as normal cubic
    		if (!sk_info->compete)
    		{
    			sk_info->compete = LEVEL_2;
    		}
    		else if (sk_info->compete == LEVEL_2)
    		{
    			sk_info->compete = LEVEL_1;
    		}
			// Just move from non-open to open, should switch to Cubic at this time
			// If the flow has never get into stable state, then temp_rate_cache is zero
			// In this case it won't know what its fair share of the bandwidth, so it will
			// recover its rate ?
			sk_info->temp_rate = sk_info->temp_rate_cache;
    		pr_info("%lu.%09lu: %u->%u recovery from packet loss, temp_rate recovery to %u \n", (unsigned long) tv.tv_sec,
    		                    (unsigned long) tv.tv_nsec, sk_info->sport, sk_info->dport, sk_info->temp_rate);
			if (sk_info->cur_tcp != TCP_CUBIC)
				switch_tcp_to(sk, sk_info, TCP_CUBIC);
			else if (sk_info->compete == LEVEL_2) {
				// Clean up all the setting..forcing cwnd to increase expotionally
				bictcp_init(sk);
			}
    	}
    }*/
}

static void try_clamp(struct sock *sk, struct socket_info *sk_info, u32 clamp)
{
	const struct tcp_sock *tp = tcp_sk(sk);
    struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_info.janus_start));
    if (clamp >= tp->snd_cwnd)
    	return;
    if (sk_info->clamp_value != clamp)
    {
        tcp_set_cwnd_clamp(sk, clamp);
        // Making sure also set ssthreshold, otherwise it will get into ssh after cwnd clamping
        tcp_set_ssthresh(sk, clamp);
        sk_info->clamp_value = clamp;
        sk_info->clamp_state = True;
        pr_info("%lu.%09lu: %u->%u, set clamp to %u \n", (unsigned long) tv.tv_sec,
                    (unsigned long) tv.tv_nsec, sk_info->sport, sk_info->dport, clamp);
    }
}

static void reset_clamp(struct sock *sk, struct socket_info *sk_info)
{
    struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_info.janus_start));
    u32 clamp = ~0;
    tcp_set_cwnd_clamp(sk, clamp);
    sk_info->clamp_state = False;
    sk_info->clamp_value = 0;
    pr_info("%lu.%09lu: %u->%u, reset clamp to ~0 \n", (unsigned long) tv.tv_sec,
            (unsigned long) tv.tv_nsec, sk_info->sport,sk_info->dport);
}

static int reduce_rate(struct sock *sk, struct socket_info *sk_info) {
	struct timespec tv = ktime_to_timespec(
			ktime_sub(ktime_get(), tcp_info.janus_start));
	const struct tcp_sock *tp = tcp_sk(sk);
	// If in slow start..do not reduce rate
	// Wait at least 1 HZ for it to shoot up
//	if ((tcp_time_stamp - sk_info->start) < HZ)
//		return False;
//	if (tcp_in_slow_start(tp))
//		return False;
	// Never reduce rate before, set it to be current time
	if (!sk_info->last_rate_reduce_ts)
	{
		sk_info->last_rate_reduce_ts = tcp_time_stamp;
		sk_info->last_rate_reduce_rtt = sk_info->rtt;
		return False;
	}
	s32 delta = tcp_time_stamp - sk_info->last_rate_reduce_ts;
	if (!sk_info->rate_reduce_inv)
		sk_info->rate_reduce_inv = 20 * ALPHA / ALPHA_SCALE;
	else
		sk_info->rate_reduce_inv = 2;
	if (delta
			< max_t(u32, HZ / 10, sk_info->rate_reduce_inv * sk_info->rtt))
		return False;
	else {
		if (sk_info->rtt_min_pre < sk_info->last_rate_reduce_rtt) {
			sk_info->last_rate_reduce_rtt = sk_info->rtt_min_pre;
			sk_info->last_rate_reduce_ts = tcp_time_stamp;
			return False;
		} else {
			s32 rtt_dev = sk_info->rtt_min_pre - sk_info->last_rate_reduce_rtt;
			u8 rtt_dev_th = sk_info->last_rate_reduce_rtt/20;
			rtt_dev_th = 2;
/*			pr_info("%lu.%09lu: %u->%u, rtt_dev_th %u \n", (unsigned long) tv.tv_sec,
						 (unsigned long) tv.tv_nsec, sk_info->sport, sk_info->dport, rtt_dev_th);*/
			return (rtt_dev > rtt_dev_th);
		}
	}
}

static int diving_cwnd(struct sock *sk, struct socket_info *sk_info)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    u32 bdp = (sk_info->est_pdelay * sk_info->temp_rate / tp->mss_cache) / HZ;
    return min_t(u32, bdp, tp->snd_cwnd);
}

static int do_slow_start(struct sock *sk, struct socket_info *sk_info)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_info.janus_start));
	if (tcp_in_slow_start(tp)) {
		// In slow start, take sample
		if (!sk_info->tp_do_smp)
			sk_info->tp_do_smp = True;
		// Update slow start timestamp
		if (!sk_info->in_slow_start)
			sk_info->in_slow_start = True;
		//u32 RATE_UP = (sk_info->rate * (ALPHA_SCALE + ALPHA)) / ALPHA_SCALE;
		u32 ssh = (sk_info->est_pdelay * sk_info->rate / tp->mss_cache) / HZ;
		if (ssh != sk_info->ssthresh) {
			sk_info->ssthresh = ssh;
			tcp_set_ssthresh(sk, sk_info->ssthresh);
			pr_info("%lu.%09lu: %u->%u update ssthresh to %u \n",
					(unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec,
					sk_info->sport, sk_info->dport, sk_info->ssthresh);
		}
		return True;
	} else {
		// Notice that this ssh setting might be overwrited by original TCP
		// The solution is that using in_slow_start to detect whether we are suppose to get out of slow start
		// If the tp->snd_ssthresh is different from out setting, then we know that this value has been overwrited
		// So we change it back and get out of slow start
		if (sk_info->in_slow_start) {
			// Override the ssh specified by original cubic
			if (sk_info->ssthresh != tp->snd_ssthresh) {
				pr_info(
						"%lu.%09lu: %u->%u sk_info->ssthresh: %u tp->snd_ssthresh: %u\n",
						(unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec,
						sk_info->sport, sk_info->dport, sk_info->ssthresh, tp->snd_ssthresh);
				tcp_set_ssthresh(sk, sk_info->ssthresh);
			} else {
				sk_info->in_slow_start = False;
			}
			return True;
		}
	}
	return False;
}

static void do_cubic(struct sock *sk, struct socket_info *sk_info)
{
    struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_info.janus_start));
	if (sk_info->clamp_state) {
		reset_clamp(sk, sk_info);
	}
	// If in slow start, re-compute the right ssh and return
	if (do_slow_start(sk, sk_info))
		return;
	// Main thing is cubic: check whether to reduce flow's temp rate
	if (reduce_rate(sk, sk_info)) {
		// If rate = 0, then there is no limit in bound
		u32 bound = sk_info->rate / 2;
		// u32 bound = 0;
		// temp rate = temp_rate*(1-a)
		u32 temp_rate = max_t(u32,
				(sk_info->temp_rate * (ALPHA_SCALE - ALPHA))
						/ ALPHA_SCALE, bound);
		if (sk_info->temp_rate != bound) {
			pr_info("%lu.%09lu: %u->%u reduce temp_rate from %u to %u\n",
					(unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec,
					sk_info->sport, sk_info->dport, sk_info->temp_rate, temp_rate);
			sk_info->temp_rate = temp_rate;
			// Remember the last min filtered RTT
			sk_info->last_rate_reduce_rtt = sk_info->rtt_min_pre;
			sk_info->last_rate_reduce_ts = tcp_time_stamp;
		}
	}
}

static inline void rate_limit(struct sock *sk, struct socket_info *sk_info)
{
	// If tp > rate*(1+alpha), increase temp_rate
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 RATE_UP = sk_info->rate * ALPHA_SCALE / (ALPHA_SCALE - ALPHA/2);
	if (sk_info->est_tp > RATE_UP) {
		u32 bdp = (sk_info->rtt_min_pre * RATE_UP / tp->mss_cache) / HZ;
		try_clamp(sk, sk_info, bdp);
	} else if (sk_info->est_tp < sk_info->rate) {
		if (sk_info->clamp_state) {
			reset_clamp(sk, sk_info);
			return;
		}
	}
}

static void init_temp_rate(struct sock *sk, struct socket_info *sk_info)
{
	struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_info.janus_start));
	const struct tcp_sock *tp = tcp_sk(sk);
	// Wait 1 Second, before setting the temp_rate
	if (tcp_in_slow_start(tp)) {
		return;
	} else {
		if (!sk_info->last_rate_reduce_ts) {
			sk_info->last_rate_reduce_ts = tcp_time_stamp;
			return;
		}
		s32 delta = tcp_time_stamp - sk_info->last_rate_reduce_ts;
		// Take care of this
		if (delta < max_t(u32, HZ / 10, 2 * sk_info->rtt))
			return;
		// Take est_tp after 1HZ as temp rate
		if (!sk_info->clamp_state) {
			u32 bdp = (sk_info->est_pdelay * sk_info->est_tp / tp->mss_cache)
					/ HZ;
			pr_info("delay: %u target rate: %u, bdp: %u \n",
					sk_info->est_pdelay, sk_info->est_tp, bdp);
			try_clamp(sk, sk_info, bdp);
			return;
		}
		sk_info->temp_rate = sk_info->est_tp;
		pr_info("%lu.%09lu: %u->%u initial temp_rate %u \n",
				(unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec,
				sk_info->sport,sk_info->dport, sk_info->temp_rate);
		if (sk_info->tp_do_smp)
			sk_info->tp_do_smp = False;
		return;
	}
}

static void do_vegas(struct sock *sk, struct socket_info *sk_info)
{
	// If the RTT is stable, update stable temp rate
	// Do we have to add checking on the RTT ?
	struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_info.janus_start));
	const struct tcp_sock *tp = tcp_sk(sk);
    if (!sk_info->temp_rate)
    {
    	init_temp_rate(sk, sk_info);
    	return;
    }
	if (sk_info->rtt_stable
			&& (sk_info->temp_rate_cache != sk_info->temp_rate)) {
		sk_info->temp_rate_cache = sk_info->temp_rate;
		pr_info("%lu.%09lu: %u->%u temp_rate_cache update to %u\n",
				(unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec,
				sk_info->sport,sk_info->dport, sk_info->temp_rate_cache);
	}
	// Think more on this...what about less then 10% of temp rate ?
	// If the rate is the same with temp_rate, and the rate is not zero (if the rate is zero we do not limit its speed)
    if (abs(sk_info->rate - sk_info->temp_rate) <= 10 && (sk_info->rate))
    {
    	rate_limit(sk, sk_info);
    }
    else
    {
        // For the competitive flow that does not set target rate
        // Why did you add the second check condition ??
        if (sk_info->clamp_state && (tp->snd_cwnd <= sk_info->clamp_value))
        {
            reset_clamp(sk, sk_info);
            return;
        }
        // Ohterwise check whether to increase temp rate or not
        u32 tmp = sk_info->temp_rate * ALPHA_SCALE / (ALPHA_SCALE - ALPHA); // tmp = temp_rate / (1-alpha)

        if (sk_info->est_tp >= tmp)
        {
            u32 temp_rate = (sk_info->rate) ? min_t(u32, tmp, sk_info->rate):tmp;
            if (sk_info->temp_rate != sk_info->rate)
            {
                pr_info("%lu.%09lu: %u->%u increase temp_rate from %u to %u\n",
                        (unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec,
                        sk_info->sport,sk_info->dport,
                        sk_info->temp_rate, temp_rate);
                sk_info->temp_rate = temp_rate;
            }
        }
    }
}


static int do_diving(struct sock *sk, struct socket_info *sk_info)
{
	return (!sk_info->clamp_state && (!sk_info->compete));
}

static inline void tcp_tuning_act(struct sock *sk, struct socket_info *sk_info)
{
    struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_info.janus_start));
    struct tcp_sock *tp = tcp_sk(sk);
    // est_pdelay, moving average of rtt
    estimate_rtt(sk, sk_info);
    // throughput
    estimate_tp(sk, sk_info);
    if (!act)
    {
    	sk_info->tp_do_smp = False;
        return;
    }
    // Only for debuging
    if (sk_info->rate == 1)
    {
    	sk_info->tp_do_smp = False;
    	return;
    }
    // queuing packet
    estimate_state(sk, sk_info);

    if (sk_info->tcp_state)
    	return;

    // slope
    //estimate_trend(sk, sk_info);
    // This does not sounds right
    if (sk_info->temp_rate)
    {
        u32 RATE_UP = sk_info->temp_rate; // temp_rate
        u32 RATE_BOT = (sk_info->temp_rate * (ALPHA_SCALE - ALPHA)) / ALPHA_SCALE;  // temp_rate * (1 - a)

        // If just join in, using tp smp, otherwise using tp avg
        if (sk_info->est_tp >= RATE_UP)
        {
            if (sk_info->cur_tcp != TCP_VEGAS)
            {
            	// The condition to diving the cwnd
            	// 1: not already in clamp state
            	// 2: not in competing mode
                if (do_diving(sk, sk_info))
                {
                    u32 target = diving_cwnd(sk, sk_info);
                    try_clamp(sk, sk_info, target);
                    return;
                }
                sk_info->tp_do_smp = False;
                switch_tcp_to(sk, sk_info, TCP_VEGAS);
                //sk_info->reduce_scale = 0;
                // Used in aggressive stage, now reset to zero
                sk_info->epo_rtt_min = sk_info->rtt;
                return;
            }
        }
        else if (sk_info->est_tp <= RATE_BOT)
        {
            if (sk_info->cur_tcp != TCP_CUBIC)
            {
            	// For reducing temp rate
            	// last_rtt: the rtt that get into cubic mode
            	// last_rate_reduce_ts: time stamp when reducing the temp rate
                sk_info->last_rate_reduce_rtt = 0;
                sk_info->last_rate_reduce_ts = 0;
                sk_info->rate_reduce_inv = 0;
                switch_tcp_to(sk, sk_info, TCP_CUBIC);
                // Just for testing.
                //bictcp_set_wmax(sk, tp->snd_cwnd + 20);
                return;
            }
        }
    }
    if (sk_info->compete)
    {
    	return;
    }
    // In temp_rate adjust part
    if (sk_info->cur_tcp == TCP_CUBIC)
    	do_cubic(sk, sk_info);
    else if (sk_info->cur_tcp == TCP_VEGAS)
    	do_vegas(sk, sk_info);
}


/* copies the probe data from the socket */
static inline void copy_to_tcp_info(struct sock *sk, struct sk_buff *skb, struct tcp_log *p, struct socket_info *sk_info)
{
    // Paying 120% attention to the saddr, daddr, it may not what you think
    // Better think this as server addr, and client addr
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_sock *inet = inet_sk(sk);
    const struct inet_connection_sock *icsk = inet_csk(sk);
    p->conn_start = sk_info->conn_start;
    p->saddr = inet->inet_saddr;
    p->sport = inet->inet_sport;
    p->daddr = inet->inet_daddr;
    p->dport = inet->inet_dport;
    p->tcp_state = icsk->icsk_ca_state;
    p->snd_nxt = tp->snd_nxt;
    p->snd_una = tp->snd_una;
    p->snd_cwnd = tp->snd_cwnd;
    p->snd_wnd = tp->snd_wnd;
    p->ssthresh = tcp_current_ssthresh(sk);
    p->length = skb == NULL ? 0 : skb->len;
    p->rtt = tp->srtt_us >> 3;
    p->rtt_min_pre = sk_info->rtt_min_pre;
    p->est_pdelay = sk_info->est_pdelay;
    p->epo_rtt_min = sk_info->epo_rtt_min;
    p->rtt_avg = sk_info->rtt_avg;
    p->tp_avg = sk_info->est_tp;
    p->temp_rate = sk_info->temp_rate;
    p->tp_smp = sk_info->est_tp_smp;
    p->inverse_slope = sk_info->inverse_slope;
    p->inverse_ssh = sk_info->inverse_ssh;
    p->rtt_stable = sk_info->rtt_stable;
    return;
}

static inline int tcptuning_sprint(struct tcp_log *p, char *tbuf, int n)
{
    struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_info.janus_start));
    int ret = scnprintf(tbuf, n, "%lu.%09lu %pI4:%u %pI4:%u  %u %u %u %u %u %u %u %u %u %u %u %u\n",
            (unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec, &p->saddr, ntohs(p->sport),
            &p->daddr, ntohs(p->dport), p->snd_cwnd, p->ssthresh,  p->rtt, p->rtt_avg, p->est_pdelay, p->epo_rtt_min,
            p->rtt_min_pre, p->tp_avg, p->tp_smp, p->temp_rate, p->inverse_slope, p->rtt_stable);
    return ret;
}


static inline void init_socket_info(struct sock *sk, struct socket_info *sk_info, struct pre_config *cfg)
{
	if (sk_info->conn_start.tv64 == 0) {
		sk_info->conn_start = ktime_get();
	}
    sk_info->last_una = tcp_sk(sk)->snd_una;
    sk_info->rate = cfg->rate;
    sk_info->temp_rate = cfg->rate;
    sk_info->temp_rate_cache = cfg->rate;
    sk_info->cur_tcp = TCP_UNCERTAIN;
}


// Not quite useful now..shoud fix later
/*
static inline void reset_socket_info(struct socket_info *sk_info)
{
    sk_info->conn_start = 0;
    sk_info->est_pdelay = 0;
    sk_info->rtt = 0;
    sk_info->rtt_min_pre = 0;
    sk_info->epo_rtt_min = 0;
    sk_info->clamp_state = 0;
    sk_info->cur_tcp = TCP_CUBIC;
    sk_info->total_byte_win = 0;
    sk_info->last_una = 0;
    sk_info->est_tp = 0;
    sk_info->temp_rate = 0;
    sk_info->last_una_ts = 0;
    sk_info->accounted = 0;
}
*/

static inline struct pre_config *find_by_key(u32 key)
{
    struct socket_hlist_item *cur;
    hash_for_each_possible(socket_htable, cur, next, key)
    {
       return cur->cfg;
    }
    return 0;
}

static inline void init_tcp(struct sock *sk, struct socket_info *sk_info)
{
	if (sk_info->rate != 1) {
		if (sk_info->rate) {
			switch_tcp_to(sk, sk_info, TCP_CUBIC);
			//sk_info->compete = LEVEL_1;
		} else {
			switch_tcp_to(sk, sk_info, TCP_VEGAS);
		}
	}
}

static inline void tcptuning_sniff(struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_sock *inet = inet_sk(sk);
    struct janus *ja = inet_csk_janus(sk);
    unsigned int head, tail;
    u32 sport, dport;
    sport = ntohs(inet->inet_sport);
    dport = ntohs(inet->inet_dport);
    spin_lock(&tcp_info.producer_lock);
    struct pre_config *cfg = find_by_key(sport);
    if (cfg)
    {
        if(!ja->sk_info)
        {
			// Set the init TCP, if rate is not 0, set up as CUBIC, otherwise set up as vegas
        	struct socket_info *tmp_info = kcalloc(bufsize, sizeof(struct socket_info), GFP_KERNEL);
			ja->sk_info = tmp_info;
			ja->sk_info->sport = sport;
			ja->sk_info->dport = dport;
			init_socket_info(sk, ja->sk_info, cfg);
			pr_info("Init Janus for connection between %u to %u \n", sport, dport);
			if (act) {
				init_tcp(sk, ja->sk_info); // This probably could fail;
			}
		}
        // reset timer
        if (!tcp_info.janus_start.tv64)
        {
            tcp_info.janus_start = ktime_get();
        }

        head = tcp_info.head;
        tail = ACCESS_ONCE(tcp_info.tail);
        // Check whether there are more space in ring buffer
        if (CIRC_SPACE(head, tail, bufsize) >= 1)
        {
            struct tcp_log *p = tcp_info.log + tcp_info.head;
            if (!act || ja->sk_info->cur_tcp != TCP_UNCERTAIN || (ja->sk_info->rate == 1))
            	tcp_tuning_act(sk, ja->sk_info);
            else
            	init_tcp(sk, ja->sk_info); // This probably could fail
            copy_to_tcp_info(sk, skb, p, ja->sk_info);
            tcp_info.head = (head + 1) & (bufsize - 1);
            wake_up(&tcp_info.wait);
        }
        tcp_info.lastcwnd = tp->snd_cwnd;
    }
    spin_unlock(&tcp_info.producer_lock);
    return;
}

/*
 * Hook inserted to be called before each released sock.
 * Note: arguments must match tcp_rcv_established()!
 */
static int jtcp_rcv_established(struct sock *sk, struct sk_buff *skb, struct tcphdr *th,
        unsigned len)
{
    tcptuning_sniff(sk, skb);
    // check whether in allow tuning list
    // check whether have saved socked before
    jprobe_return();
    return 0;
}

/*
 * Hook inserted to be called before each socket tcp.
 * Note: arguments must match tcp_close()!
 */
static void jtcp_close(struct sock *sk, long timeout)
{
    struct inet_sock *inet = inet_sk(sk);
    u32 sport,dport;
    sport = ntohs(inet->inet_sport);
    dport = ntohs(inet->inet_dport);
    struct pre_config *cfg = find_by_key(sport);
    if (cfg)
    {
        pr_info("%u->%u, connection end ! \n", sport, dport);
        //reset_socket_info(sk_info);
    }
    jprobe_return();
}


static struct jprobe tcp_close_jprobe =
{ .kp =
{ .symbol_name = "tcp_close", }, .entry = jtcp_close, };

static struct jprobe tcp_tuning_jprobe =
{ .kp =
{.symbol_name = "tcp_rcv_established", }, .entry = jtcp_rcv_established, };


static int tcptuning_open(struct inode * inode, struct file * file)
{
    /* Reset (empty) log */
    spin_lock(&tcp_info.producer_lock);
    spin_lock(&tcp_info.consumer_lock);
    tcp_info.head = tcp_info.tail = 0;

    // reset the module timer
    tcp_info.janus_start.tv64 = 0;

    spin_unlock(&tcp_info.consumer_lock);
    spin_unlock(&tcp_info.producer_lock);

    return 0;
}

static ssize_t tcptuning_read(struct file *file, char __user *buf,
        size_t len, loff_t *ppos)
{
    int error = 0;
    size_t cnt = 0;


    int eventbuf = 1;

    if (!buf)
    return -EINVAL;

    while (eventbuf >= 0 && cnt < len)
    {
        char tbuf[163];
        int width = 0;
        unsigned long head, tail;

        error = wait_event_interruptible (
                tcp_info.wait,
                CIRC_CNT(ACCESS_ONCE(tcp_info.head), tcp_info.tail, bufsize) > 0
        );

        if (error)
        break;

        spin_lock_bh(&tcp_info.consumer_lock);

        head = ACCESS_ONCE(tcp_info.head);
        tail = tcp_info.tail;

        /* re-check condition as head could have
         changed before the lock was acquired */
        if(CIRC_CNT(head, tail, bufsize) > 0)
        {
            struct tcp_log *p;

            p = tcp_info.log + tcp_info.tail;

            if (cnt + width < len)
            tcp_info.tail = (tail + 1) & (bufsize - 1);

            width = tcptuning_sprint(p, tbuf, sizeof(tbuf));
        }

        spin_unlock_bh(&tcp_info.consumer_lock);

        // if record greater than space available
        //   return partial buffer (so far)
        if (cnt + width >= len)
        {
            printk("cnt +width is >= len, breaking!\n");
            break;
        }

        if (copy_to_user(buf + cnt, tbuf, width))
        {
            //if (copy_to_user(buf, tbuf, width)) {
            printk("error copying to user!\n");
            return -EFAULT;
        }
        eventbuf--;
        cnt += width;
    }
    return cnt == 0 ? error : cnt;
}


static int tcptuning_release(struct inode *inode, struct file *file)
{
    printk("closing\n");
    return 0;
}

static struct file_operations tcptuning_fops =
{
        .owner = THIS_MODULE,
        .open = tcptuning_open,
//.write	 = tcptuning_write,
        .release = tcptuning_release,
        .read = tcptuning_read,
        .llseek = noop_llseek,
};

static inline int init_socket_htable(void)
{
    int port_len;
    char *config_entry = NULL;
    u32 port_u, rate_u;
    //pr_info("All config file: %s \n", config);
    while ((config_entry = strsep(&config, ".")) != NULL)
    {
        if (config_entry[0] == '\0')
            break;
        //pr_info("Handing config_entry: %s \n", config_entry);
        char *rate = strstr(config_entry, ":");
        if (rate <= config_entry)
        {
            pr_info("Probably error in %s \n", config_entry);
            continue;
        }
        // Important here..
        port_len = rate - config_entry + 1;
        char *port = kcalloc(port_len, sizeof(char), GFP_KERNEL);
        strncpy(port, config_entry, rate - config_entry);
        port[port_len - 1] = '\0';
        //struct socket_info *sk_info = kcalloc(bufsize, sizeof(struct socket_info), GFP_KERNEL);
        struct pre_config *cfg = kcalloc(bufsize, sizeof(struct pre_config), GFP_KERNEL);
        if (!cfg)
        {
            pr_info("Fail to allocate memory ! \n");
            return 0;
        }
        // revise here, string to int ?
        if (kstrtol(port, 10, &port_u))
        {
            pr_info("Fail to recognize port: %s\n", port);
            continue;
        }
        if (kstrtol((rate + 1), 10, &rate_u))
        {
            pr_info("Fail to recognize rate: %s\n", rate);
            continue;
        }
        cfg->sport = port_u;
        cfg->rate = rate_u;
        struct socket_hlist_item *sock_hlist = kcalloc(bufsize, sizeof(struct socket_hlist_item),
                GFP_KERNEL);
        sock_hlist->cfg = cfg;
        // if success, add it to hash table, the last argument is key
        hash_add(socket_htable, &sock_hlist->next, sock_hlist->cfg->sport);
        pr_info("Config port: %u, target rate: %u Bps\n", port_u, rate_u);
    }
    return 1;
}

static __init int tcptuning_init(void)
{
    int ret = -ENOMEM;

    pr_info("Janus starts working ! \n");
    init_waitqueue_head(&tcp_info.wait);
    spin_lock_init(&tcp_info.producer_lock);
    spin_lock_init(&tcp_info.consumer_lock);

/*    if (bufsize == 0)
    return -EINVAL;*/

    bufsize = roundup_pow_of_two(bufsize);
    tcp_info.log = kcalloc(bufsize, sizeof(struct tcp_log), GFP_KERNEL);

    if (!tcp_info.log)
        goto err0;

    if (!init_socket_htable())
            goto err0;


    if (!proc_create(procname, S_IRUSR, init_net.proc_net, &tcptuning_fops))
        goto err0;
    if (register_jprobe(&tcp_tuning_jprobe) < 0)
        goto err1;
    if (register_jprobe(&tcp_close_jprobe) < 0)
        goto err1;
    //tcp_info_init();
    return 0;

    err1:
        remove_proc_entry(procname, init_net.proc_net);
    err0:
        kfree(tcp_info.log);
    return ret;
}
module_init( tcptuning_init);

static __exit void tcptuning_exit(void)
{
    int bkt;
    struct socket_hlist_item *cur;
    remove_proc_entry(procname, init_net.proc_net);
    unregister_jprobe(&tcp_tuning_jprobe);
    unregister_jprobe(&tcp_close_jprobe);
    kfree(tcp_info.log);
    hash_for_each(socket_htable, bkt, cur, next)
    {
        kfree(cur->cfg);
    }
}
module_exit( tcptuning_exit);

