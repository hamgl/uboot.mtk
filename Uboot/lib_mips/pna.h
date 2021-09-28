#ifndef __UIP_H__
#define __UIP_H__

#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <malloc.h>
#include <common.h>


#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN  3412
#endif /* LITTLE_ENDIAN */
#ifndef BIG_ENDIAN
#define BIG_ENDIAN     1234
#endif /* BIGE_ENDIAN */


#define is_digit(c) ((c) >= '0' && (c) <= '9')

#define STATE_NONE				0		// empty state (waiting for request...)
#define STATE_FILE_REQUEST		1		// remote host sent GET request
#define STATE_UPLOAD_REQUEST	2		// remote host sent POST request

#define APP_HTTPD 0
#define APP_MCAST 1

#define UPGRADE_FIRMWARE 0
#define UPGRADE_UBOOT 1

#define GET_DEFAULT 0
#define GET_REBOOT 1

#define FLASH_UBOOT_OFFSET 0
#define FLASH_KERNEL_OFFSET 0x50000
#define PNA_LOAD_ADDRESS 0x80100000

typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef unsigned short uip_stats_t;

#define UIP_FIXEDADDR		0
#define UIP_PINGADDRCONF	0
#define UIP_FIXEDETHADDR	0
#define UIP_ETHADDR0	0x00
#define UIP_ETHADDR1	0xbd
#define UIP_ETHADDR2	0x3b
#define UIP_ETHADDR3	0x33
#define UIP_ETHADDR4	0x05
#define UIP_ETHADDR5	0x71
#define UIP_TTL         255
#define UIP_REASSEMBLY 0
#define UIP_REASS_MAXAGE 40
#define UIP_UDP           0
#define UIP_UDP_CHECKSUMS 0
#define UIP_UDP_CONNS    10
#define UIP_UDP_APPCALL  udp_appcall
#define UIP_ACTIVE_OPEN 0
#define UIP_CONNS       2
#define UIP_LISTENPORTS 1
//#define UIP_RECEIVE_WINDOW   32768
#define UIP_RECEIVE_WINDOW   3000
//#define UIP_URGDATA      0
#define UIP_URGDATA      1
#define UIP_RTO         3
#define UIP_MAXRTX      8
#define UIP_MAXSYNRTX      3
#define UIP_TCP_MSS     (UIP_BUFSIZE - UIP_LLH_LEN - 40)
#define UIP_TIME_WAIT_TIMEOUT 120
#define UIP_ARPTAB_SIZE 2
#define UIP_ARP_MAXAGE 120
#define UIP_BUFSIZE     1500
#define UIP_STATISTICS  0
#define UIP_LOGGING     0
#define UIP_LLH_LEN     14
#define BYTE_ORDER     LITTLE_ENDIAN

#ifndef UIP_APPCALL
#define UIP_APPCALL		httpd_appcall
#endif

struct httpd_state {
	u8_t state;
	u16_t count;
	u8_t *dataptr;
	unsigned int upload;
	unsigned int upload_total;
};

#ifndef UIP_APPSTATE_SIZE
#define UIP_APPSTATE_SIZE (sizeof(struct httpd_state))
#endif

extern struct httpd_state *hs;

void uip_add32(u8_t *op32, u16_t op16);
u16_t uip_chksum(u16_t *buf, u16_t len);
u16_t uip_ipchksum(void);
u16_t uip_tcpchksum(void);

struct uip_eth_addr {
	u8_t addr[6];
};
extern struct uip_eth_addr uip_ethaddr;

struct uip_eth_hdr {
	struct uip_eth_addr dest;
	struct uip_eth_addr src;
	u16_t type;
};

#define UIP_ETHTYPE_ARP 0x0806
#define UIP_ETHTYPE_IP  0x0800
#define UIP_ETHTYPE_IP6 0x86dd

void uip_arp_init(void);
void uip_arp_ipin(void);
void uip_arp_arpin(void);
void uip_arp_out(void);
void uip_arp_timer(void);

#define uip_setdraddr(addr) do { uip_arp_draddr[0] = addr[0]; uip_arp_draddr[1] = addr[1]; } while(0)
#define uip_setnetmask(addr) do { uip_arp_netmask[0] = addr[0]; uip_arp_netmask[1] = addr[1]; } while(0)
#define uip_getdraddr(addr) do { addr[0] = uip_arp_draddr[0]; addr[1] = uip_arp_draddr[1]; } while(0)
#define uip_getnetmask(addr) do { addr[0] = uip_arp_netmask[0]; addr[1] = uip_arp_netmask[1]; } while(0)
#define uip_setethaddr(eaddr) do {uip_ethaddr.addr[0] = eaddr.addr[0]; uip_ethaddr.addr[1] = eaddr.addr[1]; uip_ethaddr.addr[2] = eaddr.addr[2]; uip_ethaddr.addr[3] = eaddr.addr[3];\
                              uip_ethaddr.addr[4] = eaddr.addr[4]; uip_ethaddr.addr[5] = eaddr.addr[5];} while(0)

extern u16_t uip_arp_draddr[2],uip_arp_netmask[2];

#define uip_sethostaddr(addr) do { uip_hostaddr[0] = addr[0]; uip_hostaddr[1] = addr[1]; } while(0)
#define uip_gethostaddr(addr) do { addr[0] = uip_hostaddr[0]; addr[1] = uip_hostaddr[1]; } while(0)
void uip_init(void);
#define uip_input()        uip_process(UIP_DATA)
#define uip_periodic(conn) do { uip_conn = &uip_conns[conn]; uip_process(UIP_TIMER); } while (0)
#define uip_periodic_conn(conn) do { uip_conn = conn; uip_process(UIP_TIMER); } while (0)

extern u8_t uip_buf[UIP_BUFSIZE+2];
void uip_listen(u16_t port);
void uip_unlisten(u16_t port);
struct uip_conn *uip_connect(u16_t *ripaddr, u16_t port);
#define uip_outstanding(conn) ((conn)->len)
#define uip_send(data, len) do { uip_sappdata = (data); uip_slen = (len);} while(0)
#define uip_datalen()       uip_len
#define uip_urgdatalen()    uip_urglen
#define uip_close()         (uip_flags = UIP_CLOSE)
#define uip_abort()         (uip_flags = UIP_ABORT)
#define uip_stop()          (uip_conn->tcpstateflags |= UIP_STOPPED)
#define uip_stopped(conn)   ((conn)->tcpstateflags & UIP_STOPPED)
#define uip_restart()         do { uip_flags |= UIP_NEWDATA; uip_conn->tcpstateflags &= ~UIP_STOPPED; } while(0)
#define uip_newdata()   (uip_flags & UIP_NEWDATA)
#define uip_acked()   (uip_flags & UIP_ACKDATA)
#define uip_connected() (uip_flags & UIP_CONNECTED)
#define uip_closed()    (uip_flags & UIP_CLOSE)
#define uip_aborted()    (uip_flags & UIP_ABORT)
#define uip_timedout()    (uip_flags & UIP_TIMEDOUT)
#define uip_rexmit()     (uip_flags & UIP_REXMIT)
#define uip_poll()       (uip_flags & UIP_POLL)
#define uip_initialmss()             (uip_conn->initialmss)
#define uip_mss()             (uip_conn->mss)

struct uip_udp_conn *uip_udp_new(u16_t *ripaddr, u16_t rport);
#define uip_udp_remove(conn) (conn)->lport = 0
#define uip_udp_send(len) uip_slen = (len)
#define uip_ipaddr(addr, addr0,addr1,addr2,addr3) do { (addr)[0] = HTONS(((addr0) << 8) | (addr1)); (addr)[1] = HTONS(((addr2) << 8) | (addr3)); } while(0)

#ifndef HTONS
#   if BYTE_ORDER == BIG_ENDIAN
#      define HTONS(n) (n)
#   else /* BYTE_ORDER == BIG_ENDIAN */
#      define HTONS(n) ((((u16_t)((n) & 0xff)) << 8) | (((n) & 0xff00) >> 8))
#   endif /* BYTE_ORDER == BIG_ENDIAN */
#endif /* HTONS */
#ifndef htons
u16_t htons(u16_t val);
#endif /* htons */
extern volatile u8_t *uip_appdata;
extern volatile u8_t *uip_sappdata;
#if UIP_URGDATA > 0
extern volatile u8_t *uip_urgdata;
#endif /* UIP_URGDATA > 0 */
extern volatile u16_t uip_len, uip_slen;
#if UIP_URGDATA > 0
extern volatile u8_t uip_urglen, uip_surglen;
#endif /* UIP_URGDATA > 0 */

struct uip_conn {
	u16_t ripaddr[2];
	u16_t lport;
	u16_t rport;
	u8_t rcv_nxt[4];
	u8_t snd_nxt[4];
	u16_t len;
	u16_t mss;
	u16_t initialmss;
	u8_t sa;
	u8_t sv;
	u8_t rto;
	u8_t tcpstateflags;
	u8_t timer;
	u8_t nrtx;
	u8_t appstate[UIP_APPSTATE_SIZE];
};

extern struct uip_conn *uip_conn;
extern struct uip_conn uip_conns[UIP_CONNS];
extern volatile u8_t uip_acc32[4];

struct uip_stats {
	struct {
		uip_stats_t drop;
		uip_stats_t recv;
		uip_stats_t sent;
		uip_stats_t vhlerr;
		uip_stats_t hblenerr;
		uip_stats_t lblenerr;
		uip_stats_t fragerr;
		uip_stats_t chkerr;
		uip_stats_t protoerr;
	} ip;
	struct {
		uip_stats_t drop;
		uip_stats_t recv;
		uip_stats_t sent;
		uip_stats_t typeerr;
	} icmp;
	struct {
		uip_stats_t drop;
		uip_stats_t recv;
		uip_stats_t sent;
		uip_stats_t chkerr;
		uip_stats_t ackerr;
		uip_stats_t rst;
		uip_stats_t rexmit;
		uip_stats_t syndrop;
		uip_stats_t synrst;
	} tcp;
};

extern struct uip_stats uip_stat;
extern volatile u8_t uip_flags;
#define UIP_ACKDATA   1
#define UIP_NEWDATA   2
#define UIP_REXMIT    4
#define UIP_POLL      8
#define UIP_CLOSE     16
#define UIP_ABORT     32
#define UIP_CONNECTED 64
#define UIP_TIMEDOUT  128
void uip_process(u8_t flag);
#define UIP_DATA    1
#define UIP_TIMER   2
#define CLOSED      0
#define SYN_RCVD    1
#define SYN_SENT    2
#define ESTABLISHED 3
#define FIN_WAIT_1  4
#define FIN_WAIT_2  5
#define CLOSING     6
#define TIME_WAIT   7
#define LAST_ACK    8
#define TS_MASK     15
#define UIP_STOPPED      16
#define UIP_TCPIP_HLEN 40

typedef struct {
	u8_t vhl,tos,len[2],ipid[2],ipoffset[2],ttl,proto;
	u16_t ipchksum;
	u16_t srcipaddr[2],destipaddr[2];
	u16_t srcport,destport;
	u8_t seqno[4],ackno[4],tcpoffset,flags,wnd[2];
	u16_t tcpchksum;
	u8_t urgp[2];
	u8_t optdata[4];
} uip_tcpip_hdr;

typedef struct {
	u8_t vhl,tos,len[2],ipid[2],ipoffset[2],ttl,proto;
	u16_t ipchksum;
	u16_t srcipaddr[2],destipaddr[2];
	u8_t type,icode;
	u16_t icmpchksum;
	u16_t id, seqno;
} uip_icmpip_hdr;

typedef struct {
	u8_t vhl,tos,len[2],ipid[2],ipoffset[2],ttl,proto;
	u16_t ipchksum;
	u16_t srcipaddr[2],destipaddr[2];
	u16_t srcport,destport;
	u16_t udplen;
	u16_t udpchksum;
} uip_udpip_hdr;

#define UIP_PROTO_ICMP  1
#define UIP_PROTO_TCP   6
#define UIP_PROTO_UDP   17

#if UIP_FIXEDADDR
extern const u16_t uip_hostaddr[2];
#else /* UIP_FIXEDADDR */
extern u16_t uip_hostaddr[2];
#endif /* UIP_FIXEDADDR */

#define ARPHDR   ((struct arp_hdr *)&uip_buf[0])
#define IPBUF ((struct ethip_hdr *)&uip_buf[0])
#define IPHDR ((uip_tcpip_hdr *)&uip_buf[UIP_LLH_LEN])

#define ARP_REQUEST 1
#define ARP_REPLY   2
#define ARP_HWTYPE_ETH 1

struct arp_hdr {
	struct uip_eth_hdr ethhdr;
	u16_t hwtype;
	u16_t protocol;
	u8_t hwlen;
	u8_t protolen;
	u16_t opcode;
	struct uip_eth_addr shwaddr;
	u16_t sipaddr[2];
	struct uip_eth_addr dhwaddr;
	u16_t dipaddr[2];
};

struct ethip_hdr {
	struct uip_eth_hdr ethhdr;
	u8_t vhl,tos,len[2],ipid[2],ipoffset[2],ttl,proto;
	u16_t ipchksum;
	u16_t srcipaddr[2],destipaddr[2];
};

struct arp_entry {
	u16_t ipaddr[2];
	struct uip_eth_addr ethaddr;
	u8_t time;
};


#define MDATA_LEN 1024
#define MDATA_TYPE_FW 1
#define MDATA_TYPE_BL 2

struct mdata {
	unsigned char type;
	unsigned int idx;
	unsigned int total;
	unsigned int size;
	unsigned int datalen;
	unsigned char data[MDATA_LEN];
}__attribute__((packed));


typedef unsigned int UINT4;
typedef struct {
	UINT4 i[2];
	UINT4 buf[4];
	unsigned char in[64];
	unsigned char digest[16];
}MD5_CTX;
#endif /* __UIP_H__ */
