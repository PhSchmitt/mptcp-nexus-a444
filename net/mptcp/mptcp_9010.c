
#include <linux/module.h>
#include <net/mptcp.h>

static u32 pkt_nr = 0;

struct sched9010_priv {

};


static bool mptcp_is_9010_unavailable(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return true;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return true;

	if (tp->pf)
		return true;

	return false;
}

/* Is the sub-socket sk available to send the skb? */
static bool mptcp_is_9010_available(struct sock *sk, const struct sk_buff *skb,
			       bool zero_wnd_test)
{
	return !mptcp_is_9010_unavailable(sk);
}


static bool subflow_9010is_backup(const struct tcp_sock *tp)
{
	return tp->mptcp->rcv_low_prio || tp->mptcp->low_prio;
}

static bool subflow_9010is_active(const struct tcp_sock *tp)
{
	return !tp->mptcp->rcv_low_prio && !tp->mptcp->low_prio;
}

/* Generic function to iterate over used and unused subflows and to select the
 * best one
 */
static struct sock
*get_9010subflow_from_selectors(struct mptcp_cb *mpcb, struct sk_buff *skb,
			    bool (*selector)(const struct tcp_sock *),
			    bool zero_wnd_test, bool *force)
{
	struct sock *fastsk = NULL;
	struct sock *slowsk = NULL;
	u32 min_srtt = 0xffffffff;
	struct sock *sk;

	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);

		/* First, we choose only the wanted sks */
		if (!(*selector)(tp))
			continue;

		if (mptcp_is_9010_unavailable(sk))
			continue;

		/* set current fastsk as slowsk - if there is a faster sk, it doesn't get lost */
		if (fastsk)
			{
				slowsk = fastsk;
			}

		if (tp->srtt < min_srtt) {
			min_srtt = tp->srtt;
			fastsk = sk;
		}
		else
		{
			slowsk = sk;
		}
	}

	/* 90/10 Scheduler: Ensure, that every 10th packet doesn't use the fastest subflow */
	if (0 != pkt_nr%10)
	{
		pr_info("MPTCP 90/10 SCHEDULER: pkt-nr= %i use fastest subflow \n",pkt_nr);
		pkt_nr++;
		if (fastsk)
			return fastsk;
	}
	else
	{
		pr_info("MPTCP 90/10 SCHEDULER: pkt-nr= %i use backup subflow \n",pkt_nr);
		pkt_nr++;
		if (slowsk)
			return slowsk;
		else
		{
			/* we might have a problem but won't kill the connection */
			pr_info("MPTCP 90/10 SCHEDULER: no slowsk found - use fastsk");
			return fastsk;
		}
	}
	/* should never be reached */
	pr_info("MPTCP 90/10 SCHEDULER: no suitable socket found \n");
	return NULL;
}

/* This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the shortest RTT.
 * If all paths have full cong windows, we simply return NULL.
 *
 * Additionally, this function is aware of the backup-subflows.
 */
static struct sock *sched9010_get_available_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk;
	//true to ensure 90/10
	bool force = true;

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		pr_info("MPTCP 90/10 SCHEDULER: only one path available - bypass scheduling \n");
		sk = (struct sock *)mpcb->connection_list;
		if (!mptcp_is_9010_available(sk, skb, zero_wnd_test))
			sk = NULL;
		return sk;
	}

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_is_9010_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	/* Find the best subflow */
	sk = get_9010subflow_from_selectors(mpcb, skb, &subflow_9010is_active,
					zero_wnd_test, &force);
	if (force)
		/* one unused active sk or one NULL sk when there is at least
		 * one temporally unavailable unused active sk
		 */
		return sk;

	sk = get_9010subflow_from_selectors(mpcb, skb, &subflow_9010is_backup,
					zero_wnd_test, &force);
	if (!force)
		/* one used backup sk or one NULL sk where there is no one
		 * temporally unavailable unused backup sk
		 *
		 * the skb passed through all the available active and backups
		 * sks, so clean the path mask
		 */
		TCP_SKB_CB(skb)->path_mask = 0;
	return sk;
}

/* Reinjections occure here - disable for 90/10 scheduler */
static struct sk_buff *mptcp9010_rcv_buf_optimization(struct sock *sk, int penal)
{
		return NULL;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__mptcp9010_next_segment(struct sock *meta_sk, int *reinject)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		*reinject = 1;
	} else {
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &meta_sk->sk_socket->flags) &&
		    sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk = sched9010_get_available_subflow(meta_sk, NULL,
								   false);
			if (!subsk)
				return NULL;

			skb = mptcp9010_rcv_buf_optimization(subsk, 0);
			if (skb)
				*reinject = -1;
		}
	}
	return skb;
}

static struct sk_buff *sched9010_next_segment(struct sock *meta_sk,
					  int *reinject,
					  struct sock **subsk,
					  unsigned int *limit)
{
	struct sk_buff *skb = __mptcp9010_next_segment(meta_sk, reinject);
	unsigned int mss_now;
	struct tcp_sock *subtp;
	u16 gso_max_segs;
	u32 max_len, max_segs, window, needed;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	*subsk = sched9010_get_available_subflow(meta_sk, skb, false);
	if (!*subsk)
		return NULL;

	subtp = tcp_sk(*subsk);
	mss_now = tcp_current_mss(*subsk);

	if (!*reinject && unlikely(!tcp_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now))) {
		skb = mptcp9010_rcv_buf_optimization(*subsk, 1);
		if (skb)
			*reinject = -1;
		else
			return NULL;
	}

	/* No splitting required, as we will only send one single segment */
	if (skb->len <= mss_now)
		return skb;

	/* The following is similar to tcp_mss_split_point, but
	 * we do not care about nagle, because we will anyways
	 * use TCP_NAGLE_PUSH, which overrides this.
	 *
	 * So, we first limit according to the cwnd/gso-size and then according
	 * to the subflow's window.
	 */

	gso_max_segs = (*subsk)->sk_gso_max_segs;
	if (!gso_max_segs) /* No gso supported on the subflow's NIC */
		gso_max_segs = 1;
	max_segs = min_t(unsigned int, tcp_cwnd_test(subtp, skb), gso_max_segs);
	if (!max_segs)
		return NULL;

	max_len = mss_now * max_segs;
	window = tcp_wnd_end(subtp) - subtp->write_seq;

	needed = min(skb->len, window);
	if (max_len <= skb->len)
		/* Take max_win, which is actually the cwnd/gso-size */
		*limit = max_len;
	else
		/* Or, take the window */
		*limit = needed;

	return skb;
}

static void sched9010_init(struct sock *sk)
{
}

struct mptcp_sched_ops mptcp_sched9010 = {
	.get_subflow = sched9010_get_available_subflow,
	.next_segment = sched9010_next_segment,
	.init = sched9010_init,
	.name = "9010",
	.owner = THIS_MODULE,
};

static int __init sched9010_register(void)
{
	BUILD_BUG_ON(sizeof(struct sched9010_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched9010))
		return -1;

	return 0;
}

static void sched9010_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched9010);
}

module_init(sched9010_register);
module_exit(sched9010_unregister);

MODULE_AUTHOR("Philipp Schmitt");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP SCHEDULER 90 10");
MODULE_VERSION("0.89");

