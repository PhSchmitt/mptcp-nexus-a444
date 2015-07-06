
#include <linux/module.h>
#include <net/mptcp.h>

static unsigned char num_segments __read_mostly = 1;
module_param(num_segments, byte, 0644);
MODULE_PARM_DESC(num_segments, "The number of consecutive segments that are part of a burst");

static bool cwnd_limited __read_mostly = 0;
module_param(cwnd_limited, bool, 0644);
MODULE_PARM_DESC(cwnd_limited, "if set to 1, the scheduler tries to fill the congestion-window on all subflows");

static u32 pkt_nr = 0;

struct appchoicesched_priv {
	unsigned char quota;
};

static struct appchoicesched_priv *appchoicesched_get_priv(const struct tcp_sock *tp)
{
	return (struct appchoicesched_priv *)&tp->mptcp->mptcp_sched[0];
}

/* If the sub-socket sk available to send the skb? */
static bool mptcp_appchoicesched_is_available(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return false;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return false;

	if (tp->pf)
		return false;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been acked.
		 * (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return false;
		else if (tp->snd_una != tp->high_seq)
			return false;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return false;
	}

	return true;
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_appchoicesched_dont_reinject_skb(struct tcp_sock *tp, struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		/* TODO: we don't want to reinject on another path if possible - is this line responsible? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

/* We just look for any subflow that is available */
static struct sock *appchoicesched_get_available_subflow(struct sock *meta_sk,
		struct sk_buff *skb,
		bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk, *bestsk = NULL, *lowpriosk = NULL, *backupsk = NULL;
	u32 min_time_to_peer = 0xffffffff, lowprio_min_time_to_peer = 0xffffffff;
	int cnt_backups = 0;

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		pr_info("MPTCP appchoicesched: There is only one subflow - no multipath-security possible \n");
		bestsk = (struct sock *)mpcb->connection_list;
		if (!mptcp_appchoicesched_is_available(bestsk, skb))
			bestsk = NULL;
		return bestsk;
	}

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
			skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
					mptcp_appchoicesched_is_available(sk, skb))
				return sk;
		}
	}

	/* First, find the best subflow */
	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);

		if (tp->mptcp->rcv_low_prio || tp->mptcp->low_prio)
			cnt_backups++;

		if ((tp->mptcp->rcv_low_prio || tp->mptcp->low_prio) &&
				tp->srtt < lowprio_min_time_to_peer) {
			if (!mptcp_appchoicesched_is_available(sk, skb))
				continue;

			if (mptcp_appchoicesched_dont_reinject_skb(tp, skb)) {
				backupsk = sk;
				continue;
			}

			lowprio_min_time_to_peer = tp->srtt;
			lowpriosk = sk;
		} else if (!(tp->mptcp->rcv_low_prio || tp->mptcp->low_prio) &&
				tp->srtt < min_time_to_peer) {
			if (!mptcp_appchoicesched_is_available(sk, skb))
				continue;

			if (mptcp_appchoicesched_dont_reinject_skb(tp, skb)) {
				backupsk = sk;
				continue;
			}

			min_time_to_peer = tp->srtt;
			bestsk = sk;
		}
	}

	if (mpcb->cnt_established == cnt_backups && lowpriosk) {
		sk = lowpriosk;
	} else if (bestsk) {
		sk = bestsk;
	} else if (backupsk) {
		/* It has been sent on all subflows once - let's give it a
		 * chance again by restarting its pathmask.
		 */
		if (skb)
			TCP_SKB_CB(skb)->path_mask = 0;
		sk = backupsk;
	}
	 /* Secure Scheduler: Ensure, that every 10th packet doesn't use the fastest subflow
  * TODO: One may vary the number of derouted packets e.g. according to the RTT-difference of the links
  */
	if (0 != pkt_nr%10)
	{
		pr_debug("MPTCP-appchoicesched pkt-nr= %i use fastest subflow \n",pkt_nr);
		pkt_nr++;
		if (bestsk)
			return bestsk;
	}
	else
	{
		pr_debug("MPTCP-appchoicesched pkt-nr= %i use backup subflow \n",pkt_nr);
		pkt_nr++;
		if (lowpriosk)
			return lowpriosk;
		if (backupsk)
			return backupsk;
	}
	/* should never be reached */
	pr_debug("MPTCP-appchoicesched no suitable socket found \n");
	return NULL;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * Sets *@reinject to 0 if it is the regular send-head of the meta-sk
 * TODO we don't allow retransmit over a new path -> edit here?
 */
static struct sk_buff *__mptcp_appchoicesched_next_segment(struct sock *meta_sk, int *reinject)
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
			struct sock *subsk = appchoicesched_get_available_subflow(meta_sk, NULL,
								   false);
			if (!subsk)
				return NULL;
		}
	}
	return skb;
}

static struct sk_buff *mptcp_appchoicesched_next_segment(struct sock *meta_sk,
		int *reinject,
		struct sock **subsk,
		unsigned int *limit)
{
	struct sk_buff *skb = __mptcp_appchoicesched_next_segment(meta_sk, reinject);
	unsigned int mss_now;
	struct tcp_sock *subtp;
	u16 gso_max_segs;
	u32 max_len, max_segs, window, needed;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	*subsk = appchoicesched_get_available_subflow(meta_sk, skb, true);
	if (!*subsk)
		return NULL;

	subtp = tcp_sk(*subsk);
	mss_now = tcp_current_mss(*subsk);

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

struct mptcp_sched_ops mptcp_sched_appchoice = {
		.get_subflow = appchoicesched_get_available_subflow,
		.next_segment = mptcp_appchoicesched_next_segment,
		.name = "security",
		.owner = THIS_MODULE,
};

static int __init appchoicesched_register(void)
{
	BUILD_BUG_ON(sizeof(struct appchoicesched_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_appchoice))
		return -1;

	return 0;
}

static void appchoicesched_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_appchoice);
}

module_init(appchoicesched_register);
module_exit(appchoicesched_unregister);

MODULE_AUTHOR("Philipp Schmitt");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SECURITY MPTCP");
MODULE_VERSION("0.89");

