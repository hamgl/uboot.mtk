#include <common.h>
#include <command.h>
#include <rt_mmap.h>
#include <asm/addrspace.h>
#include <configs/rt2880.h>
#include <net.h>
#include <spi_api.h>
#include "pna.h"

#define GPIO_SYS_RST	1

extern unsigned long mips_cpu_feq;
extern BUFFER_ELEM *rt2880_free_buf_entry_dequeue(VALID_BUFFER_STRUCT *hdr);
extern VALID_BUFFER_STRUCT  rt2880_free_buf_list;
extern IPaddr_t	NetArpWaitPacketIP;
extern IPaddr_t	NetArpWaitReplyIP;
extern uchar	       *NetArpWaitPacketMAC;	/* MAC address of waiting packet's destination	*/
extern uchar          *NetArpWaitTxPacket;	/* THE transmit packet			*/
extern int		NetArpWaitTxPacketSize;
extern uchar 		NetArpWaitPacketBuf[PKTSIZE_ALIGN + PKTALIGN];
extern ulong		NetArpWaitTimerStart;
extern int		NetArpWaitTry;

unsigned int load_pos;
static int arptimer=0;
int pna_running=0,pna_upload_done=0,upgrade_type=-1,found_data=0,post_done=0,upload_failed=0,get_type=0;
char *home_page="HTTP/1.1 200 OK\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
	"<HTML><BODY>"
	"<form action=firmware method=post encType=multipart/form-data>"
	"<table border=0 cellpadding=0 cellspacing=0>"
	"<tr style='margin-bottom:5px;display:block;'><td width=100>Firmware:</td><td><input type=file size=35 name=files></td><td><input type=submit value=Upgrade><br></td></tr>"
	"</table></form>"
	"<form action=boot method=post encType=multipart/form-data>"
	"<table border=0 cellpadding=0 cellspacing=0>"
	"<tr style='margin-bottom:5px;display:block;'><td width=100>Uboot:</td><td><input type=file size=35 name=files></td><td><input type=submit value=Upgrade><br></td></tr>"
	"</table></form>"
	"<table border=0 cellpadding=0 cellspacing=0>"
	"<tr style='margin-bottom:10px;display:block;'><td><a href=reboot >Reboot</a></td></tr>"
	"</table>"
	"</BODY></HTML>";
char *error_page="HTTP/1.1 200 OK\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
	"<HTML><BODY>Operation Failed</BODY></HTML>";
char *success_page="HTTP/1.1 200 OK\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
	"<HTML><BODY>Operation Successed.<br>System is going to reboot.<br>Please wait a few moments.</BODY></HTML>";
char *boundary_value=NULL;

struct httpd_state *hs;

unsigned int gpio_get(int gpio)
{/*AMX*/
	unsigned int tmp=0;

	if(gpio <= 31)
	{
		tmp = le32_to_cpu(*(volatile u32 *)(RT2880_REG_PIODATA));
		tmp = (tmp >> gpio) & 1u;
	}
	else if(gpio <= 63)
	{
		tmp = le32_to_cpu(*(volatile u32 *)(RT2880_REG_PIODATA+4));
		tmp = (tmp >> (gpio%32)) & 1u;
	}
	return tmp;
}

void gpio_mode_set_bit(unsigned int idx,unsigned int value)
{/*AMX*/
	unsigned int tmp;

	if(idx > 31)
	{
		idx = 31;
	}
	tmp = le32_to_cpu(*(volatile u32 *)(RT2880_GPIOMODE_REG));
	if(value)
	{
		tmp |=  (1u << idx);
	}
	else
	{
		tmp &= ~(1u << idx);
	}
	*(volatile u32 *)(RT2880_GPIOMODE_REG) = cpu_to_le32(tmp);
}

void reboot(void)
{
	udelay(1000000);
	printf("rebooting...\n");
	do_reset(NULL,0,0,NULL);
}

static int atoi(const char *s)
{
	int i=0;
	while((*s != 0) && !is_digit(*s))
	{
		s++;
	}
	while(is_digit(*s))
	{
		i = i * 10 + *(s++) - '0';
	}
	return i;
}

char *strstr(const char *s1,const char *s2)
{
	int l1,l2;

	if(!(l2=strlen(s2)))
	{
		return (char *)s1;
	}
	l1 = strlen(s1);
	while(l1 >= l2)
	{
		l1--;
		if(!memcmp(s1,s2,l2))
		{
			return (char *)s1;
		}
		s1++;
	}
	return NULL;
}

void NetSend_pna(void)
{
	int i;
	volatile uchar *tmpbuf = NetTxPacket;

	for(i=0;i < 40 + UIP_LLH_LEN;i++)
	{
		tmpbuf[i] = uip_buf[i];
	}
	for(;i < uip_len;i++)
	{
		tmpbuf[i] = uip_appdata[i - 40 - UIP_LLH_LEN];
	}
	eth_send(NetTxPacket,uip_len);
}

void NetReceive_pna(volatile uchar *inpkt,int len)
{
	memcpy(uip_buf,(const void *)inpkt,len);
	uip_len = len;
	if(((struct ethip_hdr *)&uip_buf[0])->ethhdr.type == htons(UIP_ETHTYPE_IP))
	{
		uip_arp_ipin();
		uip_input();
		if(uip_len > 0)
		{
			uip_arp_out();
			NetSend_pna();
		}
	}
	else if(((struct uip_eth_hdr *)&uip_buf[0])->type == htons(UIP_ETHTYPE_ARP))
	{
		uip_arp_arpin();
		if(uip_len > 0)
		{
			NetSend_pna();
		}
	}
}

void pna_rx(int app)
{
	int i;
	for(i=0;i < UIP_CONNS;i++)
	{
		uip_periodic(i);
		if(uip_len > 0)
		{
			uip_arp_out();
			if(app == APP_HTTPD)
			{
				NetSend_pna();
			}
		}
	}
	if(++arptimer == 20)
	{
		uip_arp_timer();
		arptimer = 0;
	}
}

int pna_upgrade(const ulong size,const int type)
{
	int ret=-1;
	unsigned int offset;

	if(type == UPGRADE_UBOOT)
	{
		printf("upgrade: boot\n");
		offset = FLASH_UBOOT_OFFSET;
	}
	else
	{
		printf("upgrade: firmware\n");
		offset = FLASH_KERNEL_OFFSET;
	}
	ret = raspi_erase_write((unsigned char*)(PNA_LOAD_ADDRESS),offset,size);
	return ret;
}

int pna_loop(int app,cmd_tbl_t *cmdtp)
{
	DECLARE_GLOBAL_DATA_PTR;
	bd_t *bd = gd->bd;
	unsigned short int ip[2];
	struct uip_eth_addr eaddr;
	char ipaddr[22] = "192.168.1.1";
	ip_to_string(bd->bi_ip_addr,ipaddr);
	setenv("ipaddr",ipaddr);
	printf("ip is %s\n",ipaddr);
	IPaddr_t x = ntohl(bd->bi_ip_addr);
	NetArpWaitPacketMAC	= NULL;
	NetArpWaitTxPacket	= NULL;
	NetArpWaitPacketIP	= 0;
	NetArpWaitReplyIP	= 0;
	NetArpWaitTxPacket	= NULL;
	NetTxPacket			= NULL;

	if(!NetTxPacket)
	{
		int	i;
		BUFFER_ELEM *buf;
		buf = rt2880_free_buf_entry_dequeue(&rt2880_free_buf_list);
		NetTxPacket = buf->pbuf;

		for(i=0;i < NUM_RX_DESC;i++)
		{
			if((buf=rt2880_free_buf_entry_dequeue(&rt2880_free_buf_list)) == NULL)
			{
				printf("\n Packet Buffer is empty ! \n");
				return -1;
			}
			NetRxPackets[i] = buf->pbuf;
		}
	}
	NetTxPacket = KSEG1ADDR(NetTxPacket);

	if(!NetArpWaitTxPacket)
	{
		NetArpWaitTxPacket = &NetArpWaitPacketBuf[0] + (PKTALIGN - 1);
		NetArpWaitTxPacket -= (ulong)NetArpWaitTxPacket % PKTALIGN;
		NetArpWaitTxPacketSize = 0;
	}
	eth_halt();
	udelay(50000);
	if(eth_init(bd) < 0)
	{
		printf("\n eth_init is fail !!\n");
		return -1;
	}
	memcpy(NetOurEther, bd->bi_enetaddr, 6);
	eaddr.addr[0] = NetOurEther[0];
	eaddr.addr[1] = NetOurEther[1];
	eaddr.addr[2] = NetOurEther[2];
	eaddr.addr[3] = NetOurEther[3];
	eaddr.addr[4] = NetOurEther[4];
	eaddr.addr[5] = NetOurEther[5];
	uip_setethaddr(eaddr);

	// set ip and other addresses
	// TODO: do we need this with uIP stack?
	NetCopyIP(&NetOurIP, &x);
	NetOurGatewayIP		= getenv_IPaddr("gatewayip");
	NetOurSubnetMask	= getenv_IPaddr("netmask");

	uip_init();
	if(app == APP_HTTPD)
	{
		uip_listen(HTONS(80));
	}
	// set local host ip address
	ip[0] = htons(((x & 0xFFFF0000) >> 16));
	ip[1] = htons((x & 0x0000FFFF));
	uip_sethostaddr(ip);
	// set network mask (255.255.0.0 -> local network)
	ip[0] = htons(0xFFFF);
	ip[1] = htons (0x0000);
	uip_setnetmask(ip);
	// should we also set default router ip address?
	ip[0] = 0xFFFF;
	ip[1] = 0xFFFF;
	uip_setdraddr(ip);

	pna_running = 1;
	for(;;)
	{
		if(eth_rx() > 0)
		{
			pna_rx(app);
		}
		if(!pna_upload_done)
		{
			continue;
		}
		eth_halt();
		if(pna_upgrade(NetBootFileXferSize,upgrade_type) >= 0)
		{
			udelay(500000);
			if(upgrade_type == UPGRADE_FIRMWARE)
			{
				char *argv[2];
				char bootk_addr[20];
				sprintf(bootk_addr,"0x%X",CFG_KERN_ADDR);
				argv[1] = &bootk_addr[0];
				do_bootm(cmdtp,0,2,argv);
			}
			reboot();
		}
		break;
	}
	pna_running = 0;
	pna_upload_done = 0;
	NetBootFileXferSize = 0;
	return -1;
}

static void httpd_state_reset(void)
{
	found_data = 0;
	hs->state = STATE_NONE;
	hs->count = 0;
	hs->dataptr = 0;
	hs->upload = 0;
	hs->upload_total = 0;
	if(boundary_value)
	{
		free(boundary_value);
	}
}

static int httpd_findandstore_firstchunk(void)
{
	char *start=NULL,*end=NULL;

	if(!boundary_value)
	{
		return 0;
	}
	if((start=(char *)strstr((char *)uip_appdata,(char *)boundary_value)))
	{
		if((end=(char *)strstr((char *)start,"\r\n\r\n")))
		{
			if((end - (char *)uip_appdata) < uip_len)
			{
				end += 4;
				// last part (magic value 6): [CR][LF](boundary length)[-][-][CR][LF]
				hs->upload_total = hs->upload_total - (int)(end - start) - strlen(boundary_value) - 6;
				printf("Loading(%d):",hs->upload_total);
				// how much data we are storing now?
				hs->upload = (unsigned int)(uip_len - (end - (char *)uip_appdata));
				memcpy((void *)load_pos, (void *)end, hs->upload);
				load_pos += hs->upload;
				return 1;
			}
		}
		else
		{
			printf("W\n");
		}
	}
	return 0;
}

void httpd_appcall(void)
{
	unsigned int i;

	switch(uip_conn->lport)
	{
		case HTONS(80):
			hs = (struct httpd_state *)(uip_conn->appstate);
			if(uip_closed())
			{
				httpd_state_reset();
				uip_close();
				return;
			}
			if(uip_aborted() || uip_timedout())
			{
				goto EXIT;
			}
			if(uip_poll())
			{
				return;
			}
			if(uip_connected())
			{
				httpd_state_reset();
				return;
			}
			if(uip_newdata() && hs->state == STATE_NONE)
			{
				if(strncmp((char *)uip_appdata,"GET",3) == 0)
				{
					hs->state = STATE_FILE_REQUEST;
				}
				else if(strncmp((char *)uip_appdata,"POST",4) == 0)
				{
					hs->state = STATE_UPLOAD_REQUEST;
				}
				else
				{
					goto EXIT;
				}

				if(hs->state == STATE_FILE_REQUEST)
				{
					char line[1024],*end=NULL;

					memset(line,0,sizeof(line));
					if((end=(char *)strstr((char *)uip_appdata,"\r\n")))
					{
						memcpy(line,uip_appdata,end - (char *)uip_appdata);
					}
					if(strstr((char *)line,"reboot"))
					{
						get_type = GET_REBOOT;
						hs->dataptr = (u8_t *)success_page;
						hs->upload = strlen(success_page);
					}
					else
					{
						get_type = GET_DEFAULT;
						hs->dataptr = (u8_t *)home_page;
						hs->upload = strlen(home_page);
					}
					uip_send(hs->dataptr,(hs->upload > uip_mss() ? uip_mss() : hs->upload));
					return;
				}
				else if(hs->state == STATE_UPLOAD_REQUEST)
				{
					char *start=NULL,*end=NULL;

					uip_appdata[uip_len] = '\0';
					if(strstr((char *)uip_appdata,"firmware"))
					{
						upgrade_type = UPGRADE_FIRMWARE;
					}
					else if(strstr((char *)uip_appdata,"boot"))
					{
						upgrade_type = UPGRADE_UBOOT;
					}
					else
					{
						goto EXIT;
					}

					if(((start=(char *)strstr((char*)uip_appdata,"Content-Length:"))) && ((end=(char *)strstr(start,"\r\n"))) && (end > start))
					{
						start += 15;
						hs->upload_total = atoi(start);
					}
					else
					{
						printf("## Error: couldn't find \"Content-Length\"!\n");
						goto EXIT;
					}
					if(((start=(char *)strstr((char *)uip_appdata,"boundary="))) && (end=(char *)strstr((char *)start,"\r\n")) && (end > start))
					{
						start += 9;
						if((boundary_value=(char*)malloc(end - start + 3)))
						{
							boundary_value[0] = '-';
							boundary_value[1] = '-';
							memcpy(&boundary_value[2],start,end - start);
							boundary_value[end - start + 2] = 0;
						}
						else
						{
							printf("## Error: couldn't allocate memory for boundary!\n");
							goto EXIT;
						}
					}
					else
					{
						printf("## Error: couldn't find boundary!\n");
						goto EXIT;
					}
					load_pos = (u8_t *)PNA_LOAD_ADDRESS;
					found_data = httpd_findandstore_firstchunk() ? 1 : 0;
					return;
				}
			}
			if(uip_acked())
			{
				if(hs->state == STATE_FILE_REQUEST)
				{
					if(hs->upload <= uip_mss())
					{
						DECLARE_GLOBAL_DATA_PTR;

						httpd_state_reset();
						uip_close();

						if(get_type == GET_REBOOT)
						{
							reboot();
						}

						if(post_done)
						{
							if(!upload_failed)
							{
								pna_upload_done = 1;
							}
							post_done = 0;
							upload_failed = 0;
						}
						return;
					}
					hs->dataptr += uip_conn->len;
					hs->upload -= uip_conn->len;
					uip_send(hs->dataptr,(hs->upload > uip_mss() ? uip_mss() : hs->upload));
				}
				return;
			}
			if(uip_rexmit())
			{
				if(hs->state == STATE_FILE_REQUEST)
				{
					uip_send(hs->dataptr,(hs->upload > uip_mss() ? uip_mss() : hs->upload));
				}
				return;
			}
			if(uip_newdata())
			{
				if(hs->state == STATE_UPLOAD_REQUEST)
				{
					uip_appdata[uip_len] = '\0';
					if(!found_data)
					{
						if(!httpd_findandstore_firstchunk())
						{
							printf("W\n");
							return;
						}
						found_data = 1;
						return;
					}
					hs->upload += (unsigned int)uip_len;
					if(!upload_failed)
					{
						memcpy((void *)load_pos, (void *)uip_appdata, uip_len);
						load_pos += uip_len;
					}
					if(hs->upload >= hs->upload_total)
					{
						char *page;

						post_done = 1;
						NetBootFileXferSize = (ulong)hs->upload_total;
						page = upload_failed ? error_page : success_page;
						httpd_state_reset();
						hs->state = STATE_FILE_REQUEST;
						hs->dataptr = (u8_t *)page;
						hs->upload = strlen(page);
						uip_send(hs->dataptr,(hs->upload > uip_mss() ? uip_mss() : hs->upload));
					}
				}
				return;
			}
		break;
		default:
			uip_abort();
		break;
	}

EXIT:
	httpd_state_reset();
	uip_abort();
	return;
}

void pna(cmd_tbl_t *cmdtp)
{
	DECLARE_GLOBAL_DATA_PTR;
	int rst=0,wait=20;

#if defined (MT7620_ASIC_BOARD)
	gpio_mode_set_bit(0,1); // I2C -> GPIO
#endif
	while(wait-- > 0)
	{
		udelay(50000);
		if(!gpio_get(GPIO_SYS_RST))
		{
			while(!gpio_get(GPIO_SYS_RST))
			{
				udelay(50000);
				if(rst++ >= 200)
				{
					break;
				}
			}
			break;
		}
	}
	if(rst >= 100)
	{
		printf("enter web mode:%d\n",rst);
		eth_initialize(gd->bd);
		pna_loop(APP_HTTPD,cmdtp);
	}
}

