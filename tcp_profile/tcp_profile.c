/*
 * TCP profiling - Observe the TCP flow with kprobes.
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


MODULE_AUTHOR("Fan Zhou <zhou.fan1@husky.neu.edu>");
MODULE_DESCRIPTION("TCP profiling tool");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.1");

/* maximum amount of probes to be buffered before forced-outpvoid mdelay(ut
 * to userspace
 */
// TODO make module parameter
#define True 1
#define False 0
#define EVENT_BUF 1

static u16 bufsize = 4096;
static char *procname = "tcpprofiling";

static char *config __read_mostly;
MODULE_PARM_DESC(config, "Port list");
module_param(config, charp, 0);

MODULE_PARM_DESC(procname, "Proc name, also trace file name");
module_param(procname, charp, 0);

DEFINE_HASHTABLE(socket_htable, 16);

struct tcp_log
{
    ktime_t tstamp;
    __be32 saddr, daddr;
    __be16 sport, dport;
    u32 snd_nxt;
    u32 snd_una;
    u32 snd_wnd;
    u32 snd_cwnd;
    u32 ssthresh;
    u32 length;
    u32 rtt_avg;
    u32 rtt_smp;
    u32 tp_avg; // moving average of tp_smp
    u32 tp_smp;

};

struct socket_hlist_item {
     struct socket_info *sk_info;
     struct hlist_node next;
} ;

struct socket_info
{
    // For system states
    u32 start;
    u32 rate;
    u32 sport;
    u32 ssthresh;
    u32 rtt_smp;
    u32 rtt_avg;

    // For throughput
    u32 total_byte_win; // total byte sent in one window
    u32 est_tp_avg;   // estimate throughput
    u32 est_tp_smp;  // sampled throughput
    u32 last_una;  // last un-acked seq, used in throughput estimation
    u32 tp_left_ts;  // left end of time window
    u32 accounted;  // duplicate acked segments
    //u32 first_ag_tp;
};

static struct
{
    spinlock_t producer_lock, consumer_lock;
    wait_queue_head_t wait;
    ktime_t start;
    unsigned long head, tail;
    struct tcp_log *log;
    u32 lastcwnd;
}tcp_info;

static inline u32 filter(u32 avg, u32 smp)
{
    u32 k = ((7 * avg) + smp) >> 3;
    return k;
}

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


static inline void estimate_rtt(struct sock *sk, struct socket_info *sk_info)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    sk_info->rtt_smp = usecs_to_jiffies(tp->srtt_us >> 3);  // Transfer that into jiffer
    sk_info->rtt_avg = filter(sk_info->rtt_avg, sk_info->rtt_smp);
}

static inline void estimate_tp(struct sock *sk, struct socket_info *sk_info)
{
    s32 delta = (tcp_time_stamp - sk_info->tp_left_ts) * 1000 / HZ;  // in ms
    sk_info->total_byte_win += count_ack(sk, sk_info);
    if (delta > sk_info->rtt_smp)
    {
        sk_info->est_tp_smp = sk_info->total_byte_win * 1000 / delta;  // in byte/s
        if (sk_info->est_tp_avg == 0)
        {
            sk_info->est_tp_avg = sk_info->est_tp_smp;
        }
        else
        {
        		sk_info->est_tp_avg = filter(sk_info->est_tp_avg,sk_info->est_tp_smp);
        }
        sk_info->total_byte_win = 0;
        sk_info->tp_left_ts = tcp_time_stamp;
    }
}

static inline void tcp_start_profiling(struct sock *sk, struct socket_info *sk_info)
{
    // est_pdelay, moving average of rtt
    estimate_rtt(sk, sk_info);
    // throughput
    estimate_tp(sk, sk_info);
}

/* copies the probe data from the socket */
static inline void copy_to_tcp_info(struct sock *sk, struct sk_buff *skb, struct tcp_log *p, struct socket_info *sk_info)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_sock *inet = inet_sk(sk);
    p->tstamp = ktime_get();
    p->saddr = inet->inet_saddr;
    p->sport = inet->inet_sport;
    p->daddr = inet->inet_daddr;
    p->dport = inet->inet_dport;
    p->snd_nxt = tp->snd_nxt;
    p->snd_una = tp->snd_una;
    p->snd_cwnd = tp->snd_cwnd;
    p->snd_wnd = tp->snd_wnd;
    p->ssthresh = tcp_current_ssthresh(sk);
    p->length = skb == NULL ? 0 : skb->len;
    p->rtt_smp = sk_info->rtt_smp;
    p->rtt_avg = sk_info->rtt_avg;
    p->tp_avg = sk_info->est_tp_avg;
    p->tp_smp = sk_info->est_tp_smp;
    return;
}

static inline int tcptuning_sprint(struct tcp_log *p, char *tbuf, int n)
{
    struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_info.start));
    int ret = scnprintf(tbuf, n, "%lu.%09lu %pI4:%u %pI4:%u %u %u %u %u %u %u\n",
            (unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec, &p->saddr, ntohs(p->sport),
            &p->daddr, ntohs(p->dport), p->snd_cwnd, p->ssthresh,  p->rtt_smp, p->rtt_avg,
              p->tp_avg, p->tp_smp);
    return ret;
}


static inline void init_socket_info(struct sock *sk, struct socket_info *sk_info)
{
    sk_info->start = tcp_time_stamp;
    sk_info->last_una = tcp_sk(sk)->snd_una;
}


// Not quite useful now..shoud fix later
static inline void reset_socket_info(struct socket_info *sk_info)
{
    sk_info->start = 0;
    sk_info->rtt_smp = 0;
    sk_info->total_byte_win = 0;
    sk_info->last_una = 0;
    sk_info->est_tp_avg = 0;
    sk_info->accounted = 0;
}

static inline struct socket_info *find_by_key(u32 key)
{
    struct socket_hlist_item *cur;
    hash_for_each_possible(socket_htable, cur, next, key)
    {
       return cur->sk_info;
    }
    return 0;
}

static inline void tcptuning_sniff(struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_sock *inet = inet_sk(sk);
    struct socket_info *sk_info;
    unsigned int head, tail;
    u32 sport;
    sport = ntohs(inet->inet_sport);
    sk_info = find_by_key(sport);
    spin_lock(&tcp_info.producer_lock);
    if (sk_info)
    {
        if(!sk_info->start)
        {
            // Set the init TCP, if rate is not 0, set up as CUBIC, otherwise set up as vegas
            init_socket_info(sk, sk_info);
        }
        // reset timer
        if (tcp_info.start.tv64 == 0)
        {
            tcp_info.start = ktime_get();
        }

        head = tcp_info.head;
        tail = ACCESS_ONCE(tcp_info.tail);
        // Check whether there are more space in ring buffer
        if (CIRC_SPACE(head, tail, bufsize) >= 1)
        {
            struct tcp_log *p = tcp_info.log + tcp_info.head;
            tcp_start_profiling(sk, sk_info);
            copy_to_tcp_info(sk, skb, p, sk_info);
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
    struct inet_sock *inet;
    u32 sport;
    struct socket_info *sk_info;
    inet = inet_sk(sk);
    sport = ntohs(inet->inet_sport);
    sk_info = find_by_key(sport);
    if (sk_info)
    {
        pr_info("%u, end closing... ! \n", sk_info->sport);
        reset_socket_info(sk_info);
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
    tcp_info.start.tv64 = 0;

    spin_unlock(&tcp_info.consumer_lock);
    spin_unlock(&tcp_info.producer_lock);

    return 0;
}

static ssize_t tcptuning_read(struct file *file, char __user *buf,
        size_t len, loff_t *ppos)
{
    int error = 0;
    size_t cnt = 0;

    int eventbuf = EVENT_BUF;

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
    printk("TCP profiling starts working. See you next time.\n");
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


// Fix later
static inline int init_socket_htable(void)
{
    struct socket_info *sk_info;
    struct socket_hlist_item *sock_hlist;
    int port_len;
    char *config_entry, *rate, *port = NULL;
    u32 port_u;
    while ((config_entry = strsep(&config, ".")) != NULL)
    {
        if (config_entry[0] == '\0')
            break;
        //pr_info("Handing config_entry: %s \n", config_entry);
        rate = strstr(config_entry, ":");
        if (rate <= config_entry)
        {
            pr_info("Probably error in %s \n", config_entry);
            continue;
        }
        port_len = rate - config_entry + 1;
        port = kcalloc(port_len, sizeof(char), GFP_KERNEL);
        strncpy(port, config_entry, rate - config_entry);
        port[port_len - 1] = '\0';
        sk_info = kcalloc(bufsize, sizeof(struct socket_info), GFP_KERNEL);
        if (!sk_info)
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
        sk_info->sport = port_u;
        sock_hlist = kcalloc(bufsize, sizeof(struct socket_hlist_item),
                GFP_KERNEL);
        sock_hlist->sk_info = sk_info;
        // if success, add it to hash table, the last argument is key
        hash_add(socket_htable, &sock_hlist->next, sock_hlist->sk_info->sport);
        pr_info("Listen on port: %u\n", port_u);
    }
    return 1;
}

static __init int tcptuning_init(void)
{
    int ret = -ENOMEM;
    init_waitqueue_head(&tcp_info.wait);
    spin_lock_init(&tcp_info.producer_lock);
    spin_lock_init(&tcp_info.consumer_lock);

/*    if (bufsize == 0)
    return -EINVAL;*/

    bufsize = roundup_pow_of_two(bufsize);
    tcp_info.log = kcalloc(bufsize, sizeof(struct tcp_log), GFP_KERNEL);

    if (!tcp_info.log)
    {
        pr_info("Fail to allocate memory for tcp_info.log !\n");
        goto err0;
    }
    if (!proc_create(procname, S_IRUSR, init_net.proc_net, &tcptuning_fops))
    {
        pr_info("Fail to create process !\n");
        goto err0;
    }
    if (register_jprobe(&tcp_tuning_jprobe) < 0)
    {
        pr_info("Fail to insert hook tcp_tuning_jprobe !\n");
        goto err1;
    }
    if (register_jprobe(&tcp_close_jprobe) < 0)
    {
        pr_info("Fail to insert hook tcp_close_jprobe !\n");
        goto err1;
    }
    if (!init_socket_htable())
    {
        pr_info("Fail to init hash table !\n");
        goto err1;
    }
    pr_info("TCP profiling starts working ! \n");
    return 0;

    err0:
        kfree(tcp_info.log);
    err1:
        remove_proc_entry(procname, init_net.proc_net);
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
        kfree(cur->sk_info);
    }
}
module_exit( tcptuning_exit);
