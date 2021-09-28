#include "pna.h"

static u16_t ipaddr[2];
static u8_t i,c,arptime,tmpage;
static struct arp_entry arp_table[UIP_ARPTAB_SIZE];
struct uip_eth_addr uip_ethaddr = {{UIP_ETHADDR0,UIP_ETHADDR1,UIP_ETHADDR2,UIP_ETHADDR3,UIP_ETHADDR4,UIP_ETHADDR5}};


void uip_add32(u8_t *op32,u16_t op16)
{
	uip_acc32[3] = op32[3] + (op16 & 0xff);
	uip_acc32[2] = op32[2] + (op16 >> 8);
	uip_acc32[1] = op32[1];
	uip_acc32[0] = op32[0];
	if(uip_acc32[2] < (op16 >> 8))
	{
		++uip_acc32[1];
		if(uip_acc32[1] == 0)
		{
			++uip_acc32[0];
		}
	}
	if(uip_acc32[3] < (op16 & 0xff))
	{
		++uip_acc32[2];
		if(uip_acc32[2] == 0)
		{
			++uip_acc32[1];
			if(uip_acc32[1] == 0)
			{
				++uip_acc32[0];
			}
		}
	}
}

u16_t uip_chksum(u16_t *sdata,u16_t len)
{
	u16_t acc;
	for(acc=0;len > 1;len -= 2)
	{
		acc += *sdata;
		if(acc < *sdata)
		{
			++acc;
		}
		++sdata;
	}
	if(len == 1)
	{
		acc += htons(((u16_t)(*(u8_t *)sdata)) << 8);
		if(acc < htons(((u16_t)(*(u8_t *)sdata)) << 8))
		{
			++acc;
		}
	}
	return acc;
}

u16_t uip_ipchksum(void)
{
	return uip_chksum((u16_t *)&uip_buf[UIP_LLH_LEN],20);
}

u16_t uip_tcpchksum(void)
{
	u16_t hsum,sum;

	hsum = uip_chksum((u16_t *)&uip_buf[20 + UIP_LLH_LEN], 20);
	sum = uip_chksum((u16_t *)uip_appdata,(u16_t)(((((u16_t)(IPHDR->len[0]) << 8) + IPHDR->len[1]) - 40)));
	if((sum += hsum) < hsum)
	{
		++sum;
	}
	if((sum += IPHDR->srcipaddr[0]) < IPHDR->srcipaddr[0])
	{
		++sum;
	}
	if((sum += IPHDR->srcipaddr[1]) < IPHDR->srcipaddr[1])
	{
		++sum;
	}
	if((sum += IPHDR->destipaddr[0]) < IPHDR->destipaddr[0])
	{
		++sum;
	}
	if((sum += IPHDR->destipaddr[1]) < IPHDR->destipaddr[1])
	{
		++sum;
	}
	if((sum += (u16_t)htons((u16_t)UIP_PROTO_TCP)) < (u16_t)htons((u16_t)UIP_PROTO_TCP))
	{
		++sum;
	}
	hsum = (u16_t)htons((((u16_t)(IPHDR->len[0]) << 8) + IPHDR->len[1]) - 20);
	if((sum += hsum) < hsum)
	{
		++sum;
	}
	return sum;
}

void uip_arp_init(void)
{
	for(i=0;i < UIP_ARPTAB_SIZE;++i)
	{
		memset(arp_table[i].ipaddr,0,4);
	}
}

void uip_arp_timer(void)
{
	struct arp_entry *tabptr;

	++arptime;
	for(i=0;i < UIP_ARPTAB_SIZE; ++i)
	{
		tabptr = &arp_table[i];
		if((tabptr->ipaddr[0] | tabptr->ipaddr[1]) != 0 && arptime - tabptr->time >= UIP_ARP_MAXAGE)
		{
			memset(tabptr->ipaddr,0,4);
		}
	}
}

static void uip_arp_update(u16_t *ipaddr,struct uip_eth_addr *ethaddr)
{
	register struct arp_entry *tabptr=0;

	for(i=0;i < UIP_ARPTAB_SIZE;++i)
	{
		tabptr = &arp_table[i];
		if((tabptr->ipaddr[0] != 0 && tabptr->ipaddr[1] != 0) && (ipaddr[0] == tabptr->ipaddr[0] && ipaddr[1] == tabptr->ipaddr[1]))
		{
			memcpy(tabptr->ethaddr.addr,ethaddr->addr,6);
			tabptr->time = arptime;
			return;
		}
	}
	for(i=0;i < UIP_ARPTAB_SIZE;++i)
	{
		tabptr = &arp_table[i];
		if(tabptr->ipaddr[0] == 0 && tabptr->ipaddr[1] == 0)
		{
			break;
		}
	}
	if(i == UIP_ARPTAB_SIZE)
	{
		tmpage = 0;
		c = 0;
		for(i=0;i < UIP_ARPTAB_SIZE;++i)
		{
			tabptr = &arp_table[i];
			if(arptime - tabptr->time > tmpage)
			{
				tmpage = arptime - tabptr->time;
				c = i;
			}
		}
		i = c;
	}
	memcpy(tabptr->ipaddr,ipaddr,4);
	memcpy(tabptr->ethaddr.addr,ethaddr->addr,6);
	tabptr->time = arptime;
}

void uip_arp_ipin(void)
{
	uip_len -= sizeof(struct uip_eth_hdr);

	if(((IPBUF->srcipaddr[0] & uip_arp_netmask[0]) != (uip_hostaddr[0] & uip_arp_netmask[0]))
		|| ((IPBUF->srcipaddr[1] & uip_arp_netmask[1]) != (uip_hostaddr[1] & uip_arp_netmask[1])))
	{
		return;
	}
	uip_arp_update(IPBUF->srcipaddr,&(IPBUF->ethhdr.src));
	return;
}

void uip_arp_arpin(void)
{
	if(uip_len < sizeof(struct arp_hdr))
	{
		uip_len = 0;
		return;
	}
	uip_len = 0;

	switch(ARPHDR->opcode)
	{
		case HTONS(ARP_REQUEST):
			if(ARPHDR->dipaddr[0] == uip_hostaddr[0] && ARPHDR->dipaddr[1] == uip_hostaddr[1])
			{
				ARPHDR->opcode = HTONS(2);
				memcpy(ARPHDR->dhwaddr.addr,ARPHDR->shwaddr.addr,6);
				memcpy(ARPHDR->shwaddr.addr,uip_ethaddr.addr,6);
				memcpy(ARPHDR->ethhdr.src.addr,uip_ethaddr.addr,6);
				memcpy(ARPHDR->ethhdr.dest.addr,ARPHDR->dhwaddr.addr,6);
				ARPHDR->dipaddr[0] = ARPHDR->sipaddr[0];
				ARPHDR->dipaddr[1] = ARPHDR->sipaddr[1];
				ARPHDR->sipaddr[0] = uip_hostaddr[0];
				ARPHDR->sipaddr[1] = uip_hostaddr[1];
				ARPHDR->ethhdr.type = HTONS(UIP_ETHTYPE_ARP);
				uip_len = sizeof(struct arp_hdr);
			}
		break;
		case HTONS(ARP_REPLY):
			if(ARPHDR->dipaddr[0] == uip_hostaddr[0] && ARPHDR->dipaddr[1] == uip_hostaddr[1])
			{
				uip_arp_update(ARPHDR->sipaddr,&ARPHDR->shwaddr);
			}
		break;
	}
	return;
}

void uip_arp_out(void)
{
	struct arp_entry *tabptr=0;

	if((IPBUF->destipaddr[0] & uip_arp_netmask[0]) != (uip_hostaddr[0] & uip_arp_netmask[0])
		|| (IPBUF->destipaddr[1] & uip_arp_netmask[1]) != (uip_hostaddr[1] & uip_arp_netmask[1]))
	{/* Destination address was not on the local network, so we need to use the default router's IP address instead of the destination address when determining the MAC address. */
		ipaddr[0] = uip_arp_draddr[0];
		ipaddr[1] = uip_arp_draddr[1];
	}
	else
	{/* use the destination IP address. */
		ipaddr[0] = IPBUF->destipaddr[0];
		ipaddr[1] = IPBUF->destipaddr[1];
	}
	for(i=0;i < UIP_ARPTAB_SIZE;++i)
	{
		tabptr = &arp_table[i];
		if(ipaddr[0] == tabptr->ipaddr[0] && ipaddr[1] == tabptr->ipaddr[1])
		{
			break;
		}
	}
	if(i == UIP_ARPTAB_SIZE)
	{/* The destination address was not in our ARP table, so we overwrite the IP packet with an ARP request. */
		memset(ARPHDR->ethhdr.dest.addr,0xff,6);
		memset(ARPHDR->dhwaddr.addr,0x00,6);
		memcpy(ARPHDR->ethhdr.src.addr,uip_ethaddr.addr,6);
		memcpy(ARPHDR->shwaddr.addr,uip_ethaddr.addr,6);
		ARPHDR->dipaddr[0] = ipaddr[0];
		ARPHDR->dipaddr[1] = ipaddr[1];
		ARPHDR->sipaddr[0] = uip_hostaddr[0];
		ARPHDR->sipaddr[1] = uip_hostaddr[1];
		ARPHDR->opcode = HTONS(ARP_REQUEST); /* ARP request. */
		ARPHDR->hwtype = HTONS(ARP_HWTYPE_ETH);
		ARPHDR->protocol = HTONS(UIP_ETHTYPE_IP);
		ARPHDR->hwlen = 6;
		ARPHDR->protolen = 4;
		ARPHDR->ethhdr.type = HTONS(UIP_ETHTYPE_ARP);
		uip_appdata = &uip_buf[40 + UIP_LLH_LEN];
		uip_len = sizeof(struct arp_hdr);
		return;
	}

	/* Build an ethernet header. */
	memcpy(IPBUF->ethhdr.dest.addr,tabptr->ethaddr.addr,6);
	memcpy(IPBUF->ethhdr.src.addr,uip_ethaddr.addr,6);
	IPBUF->ethhdr.type = HTONS(UIP_ETHTYPE_IP);
	uip_len += sizeof(struct uip_eth_hdr);
}


unsigned short int uip_hostaddr[2],uip_arp_draddr[2],uip_arp_netmask[2];
u8_t uip_buf[UIP_BUFSIZE+2];   /* The packet buffer that contains incoming packets. */
volatile u8_t *uip_appdata;  /* The uip_appdata pointer points to application data. */
volatile u8_t *uip_sappdata;  /* The uip_appdata pointer points to the application data which is to be sent. */
#if UIP_URGDATA > 0
volatile u8_t *uip_urgdata;  /* The uip_urgdata pointer points to urgent data (out-of-band data), if present. */
volatile u8_t uip_urglen, uip_surglen;
#endif /* UIP_URGDATA > 0 */

volatile unsigned short int uip_len, uip_slen;  /* The uip_len is either 8 or 16 bits,depending on the maximum packet size. */
volatile u8_t uip_flags;     /* The uip_flags variable is used for communication between the TCP/IP stack and the application program. */
struct uip_conn *uip_conn;   /* uip_conn always points to the current connection. */
struct uip_conn uip_conns[UIP_CONNS]; /* The uip_conns array holds all TCP connections. */
unsigned short int uip_listenports[UIP_LISTENPORTS]; /* The uip_listenports list all currently listning ports. */
static unsigned short int ipid;           /* Ths ipid variable is an increasing	number that is used for the IP ID field. */
static u8_t iss[4];          /* The iss variable is used for the TCP initial sequence number. */
/* Temporary variables. */
volatile u8_t uip_acc32[4];
static u8_t c, opt;
static unsigned short int tmp16;

/* Structures and definitions. */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_CTL 0x3f

#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO       8

/* Macros. */
#define BUF ((uip_tcpip_hdr *)&uip_buf[UIP_LLH_LEN])
#define FBUF ((uip_tcpip_hdr *)&uip_reassbuf[0])
#define ICMPBUF ((uip_icmpip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UDPBUF ((uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])

#define UIP_LOG(m)

void uip_init(void)
{
	for(c=0;c < UIP_LISTENPORTS;++c)
	{
		uip_listenports[c] = 0;
	}
	for(c=0;c < UIP_CONNS;++c)
	{
		uip_conns[c].tcpstateflags = CLOSED;
	}
	uip_hostaddr[0] = uip_hostaddr[1] = 0;
}

void uip_unlisten(unsigned short int port)
{
	for(c=0;c < UIP_LISTENPORTS;++c)
	{
		if(uip_listenports[c] == port)
		{
			uip_listenports[c] = 0;
			return;
		}
	}
}

void uip_listen(unsigned short int port)
{
	for(c=0;c < UIP_LISTENPORTS;++c)
	{
		if(uip_listenports[c] == 0)
		{
			uip_listenports[c] = port;
			return;
		}
	}
}

static void uip_add_rcv_nxt(unsigned short int n)
{
	uip_add32(uip_conn->rcv_nxt, n);
	uip_conn->rcv_nxt[0] = uip_acc32[0];
	uip_conn->rcv_nxt[1] = uip_acc32[1];
	uip_conn->rcv_nxt[2] = uip_acc32[2];
	uip_conn->rcv_nxt[3] = uip_acc32[3];
}

void uip_process(u8_t flag)
{
	register struct uip_conn *uip_connr=uip_conn;

	uip_appdata = &uip_buf[40 + UIP_LLH_LEN];
	if(flag == UIP_TIMER)
	{
		if((++iss[3] == 0) && (++iss[2] == 0) && (++iss[1] == 0))
		{
			++iss[0];
		}
		uip_len = 0;
		if(uip_connr->tcpstateflags == TIME_WAIT || uip_connr->tcpstateflags == FIN_WAIT_2)
		{
			++(uip_connr->timer);
			if(uip_connr->timer == UIP_TIME_WAIT_TIMEOUT)
			{
				uip_connr->tcpstateflags = CLOSED;
			}
		}
		else if(uip_connr->tcpstateflags != CLOSED)
		{/* If the connection has outstanding data, we increase the connection's timer and see if it has reached the RTO value in which case we retransmit. */
			if(uip_outstanding(uip_connr))
			{
				if(uip_connr->timer-- == 0)
				{
					if(uip_connr->nrtx == UIP_MAXRTX || ((uip_connr->tcpstateflags == SYN_SENT || uip_connr->tcpstateflags == SYN_RCVD) && uip_connr->nrtx == UIP_MAXSYNRTX))
					{
						uip_connr->tcpstateflags = CLOSED;
						uip_flags = UIP_TIMEDOUT;
						UIP_APPCALL();
						BUF->flags = TCP_RST | TCP_ACK;
						goto tcp_send_nodata;
					}
					uip_connr->timer = UIP_RTO << (uip_connr->nrtx > 4 ? 4: uip_connr->nrtx); /* Exponential backoff. */
					++(uip_connr->nrtx);
					switch(uip_connr->tcpstateflags & TS_MASK)
					{
						case SYN_RCVD:
							goto tcp_send_synack;
						case ESTABLISHED:
							uip_len = 0;
							uip_slen = 0;
							uip_flags = UIP_REXMIT;
							UIP_APPCALL();
							goto apprexmit;
						case FIN_WAIT_1:
						case CLOSING:
						case LAST_ACK:
							goto tcp_send_finack;
					}
				}
			}
			else if((uip_connr->tcpstateflags & TS_MASK) == ESTABLISHED)
			{/* If there was no need for a retransmission, we poll the application for new data. */
				uip_len = 0;
				uip_slen = 0;
				uip_flags = UIP_POLL;
				UIP_APPCALL();
				goto appsend;
			}
		}
		goto drop;
	}

	if(BUF->vhl != 0x45)
	{
		UIP_LOG("ip: invalid version or header length.");
		goto drop;
	}
	if(BUF->len[0] != (uip_len >> 8))
	{/* IP length, high byte. */
		uip_len = (uip_len & 0xff) | (BUF->len[0] << 8);
	}
	if(BUF->len[1] != (uip_len & 0xff))
	{/* IP length, low byte. */
		uip_len = (uip_len & 0xff00) | BUF->len[1];
	}
	if((BUF->ipoffset[0] & 0x3f) != 0 || BUF->ipoffset[1] != 0)
	{
		UIP_LOG("ip: fragment dropped.");
		goto drop;
	}
	/* Check if the packet is destined for our IP address. */
	if(BUF->destipaddr[0] != uip_hostaddr[0])
	{
		UIP_LOG("ip: packet not for us.");
		goto drop;
	}
	if(BUF->destipaddr[1] != uip_hostaddr[1])
	{
		UIP_LOG("ip: packet not for us.");
		goto drop;
	}
	if(uip_ipchksum() != 0xffff)
	{ /* Compute and check the IP header checksum. */
		UIP_LOG("ip: bad checksum.");
		goto drop;
	}
	if(BUF->proto == UIP_PROTO_TCP)  /* Check for TCP packet. If so, jump to the tcp_input label. */
		goto tcp_input;

	if(BUF->proto != UIP_PROTO_ICMP)
	{/* We only allow ICMP packets from here. */
		UIP_LOG("ip: neither tcp nor icmp.");
		goto drop;
	}
	/* ICMP echo (i.e., ping) processing. This is simple, we only change the ICMP type from ECHO to ECHO_REPLY and adjust the ICMP checksum before we return the packet. */
	if(ICMPBUF->type != ICMP_ECHO)
	{
		UIP_LOG("icmp: not icmp echo.");
		goto drop;
	}
	/* If we are configured to use ping IP address assignment, we use the destination IP address of this ping packet and assign it to ourself. */
	ICMPBUF->type = ICMP_ECHO_REPLY;
	if(ICMPBUF->icmpchksum >= HTONS(0xffff - (ICMP_ECHO << 8)))
	{
		ICMPBUF->icmpchksum += HTONS(ICMP_ECHO << 8) + 1;
	}
	else
	{
		ICMPBUF->icmpchksum += HTONS(ICMP_ECHO << 8);
	}
	/* Swap IP addresses. */
	tmp16 = BUF->destipaddr[0];
	BUF->destipaddr[0] = BUF->srcipaddr[0];
	BUF->srcipaddr[0] = tmp16;
	tmp16 = BUF->destipaddr[1];
	BUF->destipaddr[1] = BUF->srcipaddr[1];
	BUF->srcipaddr[1] = tmp16;
	goto send;

tcp_input:
	if(uip_tcpchksum() != 0xffff)
	{   /* Compute and check the TCP checksum. */
		UIP_LOG("tcp: bad checksum.");
		goto drop;
	}
	/* Demultiplex this segment. */
	/* First check any active connections. */
	for(uip_connr = &uip_conns[0]; uip_connr < &uip_conns[UIP_CONNS]; ++uip_connr)
	{
		if(uip_connr->tcpstateflags != CLOSED && BUF->destport == uip_connr->lport && BUF->srcport == uip_connr->rport && BUF->srcipaddr[0] == uip_connr->ripaddr[0] && BUF->srcipaddr[1] == uip_connr->ripaddr[1])
		{
			goto found;
		}
	}
	/* If we didn't find and active connection that expected the packet, either this packet is an old duplicate, or this is a SYN packet destined for a connection in LISTEN. If the SYN flag isn't set,it is an old packet and we send a RST. */
	if((BUF->flags & TCP_CTL) != TCP_SYN)
	goto reset;

	tmp16 = BUF->destport;
	/* Next, check listening connections. */
	for(c = 0; c < UIP_LISTENPORTS; ++c)
	{
		if(tmp16 == uip_listenports[c])
			goto found_listen;
	}

	/* No matching connection found, so we send a RST packet. */
reset:
	/* We do not send resets in response to resets. */
	if(BUF->flags & TCP_RST)
	goto drop;

	BUF->flags = TCP_RST | TCP_ACK;
	uip_len = 40;
	BUF->tcpoffset = 5 << 4;
	/* Flip the seqno and ackno fields in the TCP header. */
	c = BUF->seqno[3];
	BUF->seqno[3] = BUF->ackno[3];
	BUF->ackno[3] = c;
	c = BUF->seqno[2];
	BUF->seqno[2] = BUF->ackno[2];
	BUF->ackno[2] = c;
	c = BUF->seqno[1];
	BUF->seqno[1] = BUF->ackno[1];
	BUF->ackno[1] = c;
	c = BUF->seqno[0];
	BUF->seqno[0] = BUF->ackno[0];
	BUF->ackno[0] = c;

	/* We also have to increase the sequence number we are	acknowledging. If the least significant byte overflowed, we need to propagate the carry to the other bytes as well. */
	if((++BUF->ackno[3] == 0) &&(++BUF->ackno[2] == 0) && (++BUF->ackno[1] == 0))
	{
		++BUF->ackno[0];
	}

	/* Swap port numbers. */
	tmp16 = BUF->srcport;
	BUF->srcport = BUF->destport;
	BUF->destport = tmp16;
	/* Swap IP addresses. */
	tmp16 = BUF->destipaddr[0];
	BUF->destipaddr[0] = BUF->srcipaddr[0];
	BUF->srcipaddr[0] = tmp16;
	tmp16 = BUF->destipaddr[1];
	BUF->destipaddr[1] = BUF->srcipaddr[1];
	BUF->srcipaddr[1] = tmp16;
	/* And send out the RST packet! */
	goto tcp_send_noconn;

	/* This label will be jumped to if we matched the incoming packet with a connection in LISTEN. In that case, we should create a new	connection and send a SYNACK in return. */
found_listen:
	/* First we check if there are any connections avaliable. Unused connections are kept in the same table as used connections, but unused ones have the tcpstate set to CLOSED. Also, connections in
	TIME_WAIT are kept track of and we'll use the oldest one if no CLOSED connections are found. Thanks to Eddie C. Dost for a very	nice algorithm for the TIME_WAIT search. */
	uip_connr = 0;
	for(c = 0; c < UIP_CONNS; ++c) {
		if(uip_conns[c].tcpstateflags == CLOSED)
		{
			uip_connr = &uip_conns[c];
			break;
		}
		if(uip_conns[c].tcpstateflags == TIME_WAIT)
		{
			if(uip_connr == 0 || uip_conns[c].timer > uip_connr->timer)
			{
				uip_connr = &uip_conns[c];
			}
		}
	}

	if(uip_connr == 0)
	{
		/* All connections are used already, we drop packet and hope that the remote end will retransmit the packet at a time when we have more spare connections. */
		UIP_LOG("tcp: found no unused connections.");
		goto drop;
	}
	uip_conn = uip_connr;

	/* Fill in the necessary fields for the new connection. */
	uip_connr->rto = uip_connr->timer = UIP_RTO;
	uip_connr->sa = 0;
	uip_connr->sv = 4;
	uip_connr->nrtx = 0;
	uip_connr->lport = BUF->destport;
	uip_connr->rport = BUF->srcport;
	uip_connr->ripaddr[0] = BUF->srcipaddr[0];
	uip_connr->ripaddr[1] = BUF->srcipaddr[1];
	uip_connr->tcpstateflags = SYN_RCVD;
	uip_connr->snd_nxt[0] = iss[0];
	uip_connr->snd_nxt[1] = iss[1];
	uip_connr->snd_nxt[2] = iss[2];
	uip_connr->snd_nxt[3] = iss[3];
	uip_connr->len = 1;
	/* rcv_nxt should be the seqno from the incoming packet + 1. */
	uip_connr->rcv_nxt[3] = BUF->seqno[3];
	uip_connr->rcv_nxt[2] = BUF->seqno[2];
	uip_connr->rcv_nxt[1] = BUF->seqno[1];
	uip_connr->rcv_nxt[0] = BUF->seqno[0];
	uip_add_rcv_nxt(1);

	/* Parse the TCP MSS option, if present. */
	if((BUF->tcpoffset & 0xf0) > 0x50) {
	for(c = 0; c < ((BUF->tcpoffset >> 4) - 5) << 2 ;) {
	opt = uip_buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + c];
	if(opt == 0x00) {
	/* End of options. */
	break;
	} else if(opt == 0x01) {
	++c;
	/* NOP option. */
	} else if(opt == 0x02 &&
	uip_buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 1 + c] == 0x04) {
	/* An MSS option with the right option length. */
	tmp16 = ((unsigned short int)uip_buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 2 + c] << 8) | (unsigned short int)uip_buf[40 + UIP_LLH_LEN + 3 + c];
	uip_connr->initialmss = uip_connr->mss = tmp16 > UIP_TCP_MSS? UIP_TCP_MSS: tmp16;

	/* And we are done processing options. */
	break;
	} else {
	/* All other options have a length field, so that we easily
	can skip past them. */
	if(uip_buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 1 + c] == 0) {
	/* If the length field is zero, the options are malformed
	and we don't process them further. */
	break;
	}
	c += uip_buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 1 + c];
	}
	}
	}

	/* Our response will be a SYNACK. */
	tcp_send_synack:
	BUF->flags = TCP_SYN | TCP_ACK;

	/* We send out the TCP Maximum Segment Size option with our	SYNACK. */
	BUF->optdata[0] = 2;
	BUF->optdata[1] = 4;
	BUF->optdata[2] = (UIP_TCP_MSS) / 256;
	BUF->optdata[3] = (UIP_TCP_MSS) & 255;
	uip_len = 44;
	BUF->tcpoffset = 6 << 4;
	goto tcp_send;

	/* This label will be jumped to if we found an active connection. */
found:
	uip_conn = uip_connr;
	uip_flags = 0;

	/* We do a very naive form of TCP reset processing; we just accept any RST and kill our connection. We should in fact check if the sequence number of this reset is wihtin our advertised window before we accept the reset. */
	if(BUF->flags & TCP_RST) {
	uip_connr->tcpstateflags = CLOSED;
	UIP_LOG("tcp: got reset, aborting connection.");
	uip_flags = UIP_ABORT;
	UIP_APPCALL();
	goto drop;
	}
	/* Calculated the length of the data, if the application has sent any data to us. */
	c = (BUF->tcpoffset >> 4) << 2;
	/* uip_len will contain the length of the actual TCP data. This is calculated by subtracing the length of the TCP header (inc) and the length of the IP header (20 bytes). */
	uip_len = uip_len - c - 20;

	/* First, check if the sequence number of the incoming packet is what we're expecting next. If not, we send out an ACK with the correct numbers in. */
	if(uip_len > 0 && (BUF->seqno[0] != uip_connr->rcv_nxt[0] || BUF->seqno[1] != uip_connr->rcv_nxt[1] || BUF->seqno[2] != uip_connr->rcv_nxt[2] || BUF->seqno[3] != uip_connr->rcv_nxt[3]))
	{
	goto tcp_send_ack;
	}

	/* Next, check if the incoming segment acknowledges any outstanding data. If so, we update the sequence number, reset the length of the outstanding data, calculate RTT estimations, and reset the retransmission timer. */
	if((BUF->flags & TCP_ACK) && uip_outstanding(uip_connr)) {
	uip_add32(uip_connr->snd_nxt, uip_connr->len);
	if(BUF->ackno[0] == uip_acc32[0] && BUF->ackno[1] == uip_acc32[1] && BUF->ackno[2] == uip_acc32[2] && BUF->ackno[3] == uip_acc32[3])
	{
	/* Update sequence number. */
	uip_connr->snd_nxt[0] = uip_acc32[0];
	uip_connr->snd_nxt[1] = uip_acc32[1];
	uip_connr->snd_nxt[2] = uip_acc32[2];
	uip_connr->snd_nxt[3] = uip_acc32[3];
	/* Do RTT estimation, unless we have done retransmissions. */
	if(uip_connr->nrtx == 0) {
	signed char m;
	m = uip_connr->rto - uip_connr->timer;
	/* This is taken directly from VJs original code in his paper */
	m = m - (uip_connr->sa >> 3);
	uip_connr->sa += m;
	if(m < 0) {
	m = -m;
	}
	m = m - (uip_connr->sv >> 2);
	uip_connr->sv += m;
	uip_connr->rto = (uip_connr->sa >> 3) + uip_connr->sv;
	}
	/* Set the acknowledged flag. */
	uip_flags = UIP_ACKDATA;
	/* Reset the retransmission timer. */
	uip_connr->timer = uip_connr->rto;
	}

	}

	/* Do different things depending on in what state the connection is. */
	switch(uip_connr->tcpstateflags & TS_MASK) {
	/* CLOSED and LISTEN are not handled here. CLOSE_WAIT is not implemented, since we force the application to close when the peer sends a FIN (hence the application goes directly from ESTABLISHED to LAST_ACK). */
	case SYN_RCVD:
	/* In SYN_RCVD we have sent out a SYNACK in response to a SYN, and we are waiting for an ACK that acknowledges the data we sent out the last time. Therefore, we want to have the UIP_ACKDATA flag set. If so, we enter the ESTABLISHED state. */
	if(uip_flags & UIP_ACKDATA) {
	uip_connr->tcpstateflags = ESTABLISHED;
	uip_flags = UIP_CONNECTED;
	uip_connr->len = 0;
	if(uip_len > 0) {
	uip_flags |= UIP_NEWDATA;
	uip_add_rcv_nxt(uip_len);
	}
	uip_slen = 0;
	UIP_APPCALL();
	goto appsend;
	}
	goto drop;

	case ESTABLISHED:
	/* In the ESTABLISHED state, we call upon the application to feed data into the uip_buf. If the UIP_ACKDATA flag is set, the application should put new data into the buffer, otherwise we are retransmitting an old segment, and the application should put that data into the buffer.
	If the incoming packet is a FIN, we should close the connection on this side as well, and we send out a FIN and enter the LAST_ACK state. We require that there is no outstanding data; otherwise the sequence numbers will be screwed up. */

	if(BUF->flags & TCP_FIN) {
	if(uip_outstanding(uip_connr)) {
	goto drop;
	}
	uip_add_rcv_nxt(1 + uip_len);
	uip_flags = UIP_CLOSE;
	if(uip_len > 0) {
	uip_flags |= UIP_NEWDATA;
	}
	UIP_APPCALL();
	uip_connr->len = 1;
	uip_connr->tcpstateflags = LAST_ACK;
	uip_connr->nrtx = 0;
	tcp_send_finack:
	BUF->flags = TCP_FIN | TCP_ACK;
	goto tcp_send_nodata;
	}

	/* Check the URG flag. If this is set, the segment carries urgent data that we must pass to the application. */
	if(BUF->flags & TCP_URG) {
	#if UIP_URGDATA > 0
	uip_urglen = (BUF->urgp[0] << 8) | BUF->urgp[1];
	if(uip_urglen > uip_len) {
	/* There is more urgent data in the next segment to come. */
	uip_urglen = uip_len;
	}
	uip_add_rcv_nxt(uip_urglen);
	uip_len -= uip_urglen;
	uip_urgdata = uip_appdata;
	uip_appdata += uip_urglen;
	} else {
	uip_urglen = 0;
	#endif /* UIP_URGDATA > 0 */
	uip_appdata += (BUF->urgp[0] << 8) | BUF->urgp[1];
	uip_len -= (BUF->urgp[0] << 8) | BUF->urgp[1];
	}
	/* If uip_len > 0 we have TCP data in the packet, and we flag this by setting the UIP_NEWDATA flag and update the sequence number we acknowledge. If the application has stopped the dataflow	using uip_stop(), we must not accept any data packets from the remote host. */
	if(uip_len > 0 && !(uip_connr->tcpstateflags & UIP_STOPPED)) {
	uip_flags |= UIP_NEWDATA;
	uip_add_rcv_nxt(uip_len);
	}

	/* Check if the available buffer space advertised by the other end is smaller than the initial MSS for this connection. If so, we set the current MSS to the window size to ensure that the	application does not send more data than the other end can handle.
	If the remote host advertises a zero window, we set the MSS to the initial MSS so that the application will send an entire MSS of data. This data will not be acknowledged by the receiver, and the application will retransmit it. This is called the "persistent timer" and uses the retransmission mechanim.*/
	tmp16 = ((unsigned short int)BUF->wnd[0] << 8) + (unsigned short int)BUF->wnd[1];
	if(tmp16 > uip_connr->initialmss || tmp16 == 0) {
	tmp16 = uip_connr->initialmss;
	}
	uip_connr->mss = tmp16;

	/* If this packet constitutes an ACK for outstanding data (flagged by the UIP_ACKDATA flag, we should call the application since it might want to send more data. If the incoming packet had data from the peer (as flagged by the UIP_NEWDATA flag), the application must also be notified.
	When the application is called, the global variable uip_len contains the length of the incoming data. The application can access the incoming data through the global pointer uip_appdata, which usually points 40 bytes into the uip_bu farray.
	If the application wishes to send any data, this data should be	put into the uip_appdata and the length of the data should be put into uip_len. If the application don't have any data to send, uip_len must be set to 0. */
	if(uip_flags & (UIP_NEWDATA | UIP_ACKDATA)) {
	uip_slen = 0;
	UIP_APPCALL();
appsend:
	if(uip_flags & UIP_ABORT) {
	uip_slen = 0;
	uip_connr->tcpstateflags = CLOSED;
	BUF->flags = TCP_RST | TCP_ACK;
	goto tcp_send_nodata;
	}

	if(uip_flags & UIP_CLOSE) {
	uip_slen = 0;
	uip_connr->len = 1;
	uip_connr->tcpstateflags = FIN_WAIT_1;
	uip_connr->nrtx = 0;
	BUF->flags = TCP_FIN | TCP_ACK;
	goto tcp_send_nodata;
	}

	/* If uip_slen > 0, the application has data to be sent. */
	if(uip_slen > 0) {
	/* If the connection has acknowledged data, the contents of the ->len variable should be discarded. */
	if((uip_flags & UIP_ACKDATA) != 0) {
	uip_connr->len = 0;
	}

	/* If the ->len variable is non-zero the connection has	already data in transit and cannot send anymore right now. */
	if(uip_connr->len == 0) {
	/* The application cannot send more than what is allowed by the mss (the minumum of the MSS and the available window). */
	if(uip_slen > uip_connr->mss) {
	uip_slen = uip_connr->mss;
	}
	/* Remember how much data we send out now so that we know when everything has been acknowledged. */
	uip_connr->len = uip_slen;
	} else {

	/* If the application already had unacknowledged data, we make sure that the application does not send (i.e., retransmit) out more than it previously sent out. */
	uip_slen = uip_connr->len;
	}
	} else {
	uip_connr->len = 0;
	}
	uip_connr->nrtx = 0;
	apprexmit:
	uip_appdata = uip_sappdata;

	/* If the application has data to be sent, or if the incoming packet had new data in it, we must send out a packet. */
	if(uip_slen > 0 && uip_connr->len > 0) {
	/* Add the length of the IP and TCP headers. */
	uip_len = uip_connr->len + UIP_TCPIP_HLEN;
	/* We always set the ACK flag in response packets. */
	BUF->flags = TCP_ACK | TCP_PSH;
	/* Send the packet. */
	goto tcp_send_noopts;
	}
	/* If there is no data to send, just send out a pure ACK if there is newdata. */
	if(uip_flags & UIP_NEWDATA) {
	uip_len = UIP_TCPIP_HLEN;
	BUF->flags = TCP_ACK;
	goto tcp_send_noopts;
	}
	}
	goto drop;
	case LAST_ACK:
	/* We can close this connection if the peer has acknowledged our FIN. This is indicated by the UIP_ACKDATA flag. */
	if(uip_flags & UIP_ACKDATA) {
	uip_connr->tcpstateflags = CLOSED;
	uip_flags = UIP_CLOSE;
	UIP_APPCALL();
	}
	break;

	case FIN_WAIT_1:
	/* The application has closed the connection, but the remote host hasn't closed its end yet. Thus we do nothing but wait for a FIN from the other side. */
	if(uip_len > 0) {
	uip_add_rcv_nxt(uip_len);
	}
	if(BUF->flags & TCP_FIN) {
	if(uip_flags & UIP_ACKDATA) {
	uip_connr->tcpstateflags = TIME_WAIT;
	uip_connr->timer = 0;
	uip_connr->len = 0;
	} else {
	uip_connr->tcpstateflags = CLOSING;
	}
	uip_add_rcv_nxt(1);
	uip_flags = UIP_CLOSE;
	UIP_APPCALL();
	goto tcp_send_ack;
	} else if(uip_flags & UIP_ACKDATA) {
	uip_connr->tcpstateflags = FIN_WAIT_2;
	uip_connr->len = 0;
	goto drop;
	}
	if(uip_len > 0) {
	goto tcp_send_ack;
	}
	goto drop;

	case FIN_WAIT_2:
	if(uip_len > 0) {
	uip_add_rcv_nxt(uip_len);
	}
	if(BUF->flags & TCP_FIN) {
	uip_connr->tcpstateflags = TIME_WAIT;
	uip_connr->timer = 0;
	uip_add_rcv_nxt(1);
	uip_flags = UIP_CLOSE;
	UIP_APPCALL();
	goto tcp_send_ack;
	}
	if(uip_len > 0) {
	goto tcp_send_ack;
	}
	goto drop;

	case TIME_WAIT:
	goto tcp_send_ack;

	case CLOSING:
	if(uip_flags & UIP_ACKDATA) {
	uip_connr->tcpstateflags = TIME_WAIT;
	uip_connr->timer = 0;
	}
	}
	goto drop;

	/* We jump here when we are ready to send the packet, and just want to set the appropriate TCP sequence numbers in the TCP header. */
	tcp_send_ack:
	BUF->flags = TCP_ACK;
	tcp_send_nodata:
	uip_len = 40;
	tcp_send_noopts:
	BUF->tcpoffset = 5 << 4;
	tcp_send:
	/* We're done with the input processing. We are now ready to send a reply. Our job is to fill in all the fields of the TCP and IP headers before calculating the checksum and finally send the packet. */
	BUF->ackno[0] = uip_connr->rcv_nxt[0];
	BUF->ackno[1] = uip_connr->rcv_nxt[1];
	BUF->ackno[2] = uip_connr->rcv_nxt[2];
	BUF->ackno[3] = uip_connr->rcv_nxt[3];
	BUF->seqno[0] = uip_connr->snd_nxt[0];
	BUF->seqno[1] = uip_connr->snd_nxt[1];
	BUF->seqno[2] = uip_connr->snd_nxt[2];
	BUF->seqno[3] = uip_connr->snd_nxt[3];
	BUF->proto = UIP_PROTO_TCP;
	BUF->srcport  = uip_connr->lport;
	BUF->destport = uip_connr->rport;
	BUF->srcipaddr[0] = uip_hostaddr[0];
	BUF->srcipaddr[1] = uip_hostaddr[1];
	BUF->destipaddr[0] = uip_connr->ripaddr[0];
	BUF->destipaddr[1] = uip_connr->ripaddr[1];
	if(uip_connr->tcpstateflags & UIP_STOPPED) {
	/* If the connection has issued uip_stop(), we advertise a zero	window so that the remote host will stop sending data. */
	BUF->wnd[0] = BUF->wnd[1] = 0;
	} else {
	BUF->wnd[0] = ((UIP_RECEIVE_WINDOW) >> 8);
	BUF->wnd[1] = ((UIP_RECEIVE_WINDOW) & 0xff);
	}
	tcp_send_noconn:
	BUF->len[0] = (uip_len >> 8);
	BUF->len[1] = (uip_len & 0xff);
	/* Calculate TCP checksum. */
	BUF->tcpchksum = 0;
	BUF->tcpchksum = ~(uip_tcpchksum());
	//ip_send_nolen:
	BUF->vhl = 0x45;
	BUF->tos = 0;
	BUF->ipoffset[0] = BUF->ipoffset[1] = 0;
	BUF->ttl  = UIP_TTL;
	++ipid;
	BUF->ipid[0] = ipid >> 8;
	BUF->ipid[1] = ipid & 0xff;
	/* Calculate IP checksum. */
	BUF->ipchksum = 0;
	BUF->ipchksum = ~(uip_ipchksum());
	send:
	/* Return and let the caller do the actual transmission. */
	return;

drop:
	uip_len = 0;
	return;
}
