/****************************************************************
 *
 *        Copyright 2013, Big Switch Networks, Inc.
 *
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *        http://www.eclipse.org/legal/epl-v10.html
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

#include <lldpa/lldpa_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>

#include <AIM/aim.h>
#include <lldpa/lldpa.h>

#ifdef USE_OS_ALARM
extern uint32_t os_alarm_register  (unsigned int when, unsigned int flags,
									int (*cb)(void* arg), void *ca);
extern void os_alarm_unregister (unsigned int alarm_id);
#endif

typedef struct octets_buf {
	size_t   len;
	octets_t *buf;
} octets_buf_t;

#define NUMPORT 1
#define CTRLID 1
lldpa_port_t* PortList[NUMPORT];
octets_buf_t Tx_Pkt_Q[NUMPORT];
octets_buf_t Tx_Pkt_Q_Expected[NUMPORT];

octets_buf_t Tx_Ctrl_Msg_Q[CTRLID];
octets_buf_t Tx_Ctrl_Msg_Q_Expected[CTRLID];

uint32_t Lldppdu_Tx[4] = {1, 1001, 1002, 1003};
uint32_t Lldppdu_Rx[4] = {1, 2001, 2002, 2003};
of_bsn_header_t PKT =
{
	.version = 0,
	.type    = 4,
	.length  = sizeof(PKT),
	.xid     = 0,
	.experimenter = 0x5c16c7,
	.subtype = 0,
	.status  = 0,
	.port_no = 0,
	.slot_num = 0,
	.interval_ms = 0
};

struct bsn_pkt_in {
	of_bsn_header_t hdr;
	uint32_t payload[4];
} PKT_IN =
{
	.payload = {1, 2001, 2002, 2003} //Must be equal Lldppdu_Rx
};

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 8
#endif

void hexdump(void *mem, unsigned int len)
{
	unsigned int i, j;

	for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
	{
		/* print offset */
		if(i % HEXDUMP_COLS == 0)
		{
			printf("0x%06x: ", i);
		}

		/* print hex data */
		if(i < len)
		{
			printf("%02x ", 0xFF & ((char*)mem)[i]);
		}
		else /* end of block, just aligning for ASCII dump */
		{
			printf("   ");
		}

		/* print ASCII dump */
		if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
		{
			for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
			{
				if(j >= len) /* end of block, not really printing */
				{
					putchar(' ');
				}
				else if(isprint(((char*)mem)[j])) /* printable char */
				{
					putchar(0xFF & ((char*)mem)[j]);
				}
				else /* other char */
				{
					putchar('.');
				}
			}
			putchar('\n');
		}
	}
}

int
os_fwd_pkt_out(void* buf, size_t count, of_port_no_t port)
{
	int idx = port-1;
	assert((0 <=idx) && (idx <NUMPORT));
	Tx_Pkt_Q[idx].buf = (octets_t *)malloc(count);
	if(!Tx_Pkt_Q[idx].buf){
		printf("OS_FWD PKT Out of Mem = %d\n", (int)count);
		exit(1);
	}
	Tx_Pkt_Q[idx].len = count;
	memcpy(Tx_Pkt_Q[idx].buf,buf,count);
	printf("OS_FWD PKT Sent = %d\n", (int)count);
	return count;
}

int
os_send_ctrl_msg(void* buf, size_t count, of_port_no_t ctrl_cxn_id)
{
	int idx = ctrl_cxn_id-1;
	assert((0<=idx) && (idx <NUMPORT));
	if (Tx_Ctrl_Msg_Q[idx].buf){
		printf("OS_SND_CTRL Controller not consume buf yet = %d\n", (int)count);
		exit(1);
	}

	Tx_Ctrl_Msg_Q[idx].buf = (octets_t *)malloc(count);
	if(!Tx_Ctrl_Msg_Q[idx].buf){
		printf("OS_SND_CTRL PKT Out of Mem = %d\n", (int)count);
		exit(1);
	}

	Tx_Ctrl_Msg_Q[idx].len = count;
	memcpy(Tx_Ctrl_Msg_Q[idx].buf,buf,count);
	printf("OS_SND_CTRL MSG Sent = %d, buf[1]=%d\n", (int)count, (int)((char*)buf)[1] );
	return count;

}

octets_t *
gen_pkt(uint32_t subtype, uint32_t time_ms, uint32_t port_no, octets_t *buf,  uint32_t len)
{
	octets_t* pkt = NULL;
	of_bsn_header_t *hdr = NULL;
	pkt = (octets_t*) malloc(sizeof(of_bsn_header_t)+len);
	if (!pkt)
		return pkt;

	memcpy (pkt, &PKT, sizeof(of_bsn_header_t));
	hdr = (of_bsn_header_t *) pkt;
	hdr->subtype = subtype;
	hdr->port_no = port_no;
	hdr->length  = sizeof(of_bsn_header_t) + len;
	hdr->interval_ms = time_ms;
	memcpy ((pkt+sizeof(of_bsn_header_t)),buf,len);
	return pkt;
}

/* Return 1 if correct / expected */
int
is_fwd_packet_correct(uint32_t port_no, int expected)
{
	int ret = 0;
	int idx = port_no-1;
	octets_buf_t *obuf;

    assert((0<=idx) && (idx <NUMPORT));
	if (!Tx_Pkt_Q[idx].buf || !Tx_Pkt_Q_Expected[idx].buf) {
		printf ("port %u not see TX pkt yet or not expected\n", port_no);
		if (!expected)
			ret = 1;
	} else {
		obuf = &Tx_Pkt_Q_Expected[idx];
		ret = memcmp(Tx_Pkt_Q[idx].buf, obuf->buf, obuf->len);
		if (expected && !ret)
			ret = 1;
		else
			ret = 0;

		free(Tx_Pkt_Q[idx].buf);
		Tx_Pkt_Q[idx].buf = NULL;
		Tx_Pkt_Q[idx].len = 0;
	}

	return ret;
}

int
is_snd_ctrl_msg_correct (uint32_t ctrl_id, int expected)
{
	int ret = 0;
	int idx = ctrl_id-1;
	octets_buf_t *obuf;

    assert((0<=idx) && (idx <NUMPORT));
	if (!Tx_Ctrl_Msg_Q[idx].buf || !Tx_Ctrl_Msg_Q_Expected[idx].buf) {
		printf ("CTRL %u not see msg yet or not expected\n", ctrl_id);
		if (!expected)
			ret = 1;
	} else {
		obuf = &Tx_Ctrl_Msg_Q_Expected[idx];

		ret = memcmp(Tx_Ctrl_Msg_Q[idx].buf, obuf->buf, obuf->len);

		if (expected && !ret)
			ret = 1;
		else {
			ret = 0;
			hexdump(Tx_Ctrl_Msg_Q[idx].buf,Tx_Ctrl_Msg_Q[idx].len);
			hexdump(Tx_Ctrl_Msg_Q_Expected[idx].buf,Tx_Ctrl_Msg_Q_Expected[idx].len);
		}
		free(Tx_Ctrl_Msg_Q[idx].buf);
		Tx_Ctrl_Msg_Q[idx].buf = NULL;
		Tx_Ctrl_Msg_Q[idx].len = 0;
	}

	return ret;
}

/* Send Req Start Pkt
 * Wait and check msg 2 times
 * Then Send Req Stop Pkt
 * Wait and check msg 2 times
 */
int test_1_simple_TX_REQ(lldpa_port_t *lldpa)
{
	int i, ret = 0;
	octets_t *pkt = NULL;
	uint32_t time_ms = 0;

	/*1. Gen the TX Req Start packet */
	octets_buf_t *lldp_pdu = &Tx_Pkt_Q_Expected[lldpa->port_no-1];
	lldp_pdu->buf = (octets_t *)Lldppdu_Tx;
	lldp_pdu->len = sizeof(Lldppdu_Tx);

	time_ms = 4;
	printf("Send RX-REQ Start Message\n");
	pkt = gen_pkt(SW_CONTR_TX_REQ, time_ms, lldpa->port_no,lldp_pdu->buf , lldp_pdu->len);
	if (!pkt)
		return -1;



	lldpa_agent_handle_msg (lldpa, pkt);
	free(pkt);

	PKT.subtype = SW_CONTR_TX_RES;
	PKT.length = sizeof(PKT);
	PKT.interval_ms = time_ms;
	PKT.port_no     = lldpa->port_no;
	Tx_Ctrl_Msg_Q_Expected[lldpa->port_no-1].buf = (octets_t*)&PKT;
	Tx_Ctrl_Msg_Q_Expected[lldpa->port_no-1].len = sizeof(PKT);
	is_snd_ctrl_msg_correct(os_ctrl_cxn_id, 1) == 1 ?
					printf("CTRL:CORRECT\n") : printf("CTRL:WRONG\n");

	/*2. Will expect TX packet every interval
	 *   Do it 2 times
	 */
	i = 2;
	time_ms = 4;
	while (i-- > 0) {
		printf("sleep ... %u\n", time_ms);
		sleep(time_ms);
		printf("sleep WAKEUP and check MS\n");
		is_fwd_packet_correct(lldpa->port_no, 1) == 1 ?
				printf("%d:CORRECT\n", i) : printf("%d:WRONG\n", i);
	}

	/*3. Gen the TX Req Stop packet */
	sleep(2);
	time_ms = 0;
	pkt = gen_pkt(SW_CONTR_TX_REQ, time_ms, lldpa->port_no, (octets_t *)Lldppdu_Tx, sizeof(Lldppdu_Tx));
	if (!pkt)
		return -1;

	printf("Send RX-REQ Stop Message\n");
	lldpa_agent_handle_msg (lldpa, pkt);
	free(pkt);

	PKT.subtype = SW_CONTR_TX_RES;
	PKT.length = sizeof(PKT);
	PKT.interval_ms = time_ms;
	PKT.port_no     = lldpa->port_no;
	Tx_Ctrl_Msg_Q_Expected[lldpa->port_no-1].buf = (octets_t*)&PKT;
	Tx_Ctrl_Msg_Q_Expected[lldpa->port_no-1].len = sizeof(PKT);
	is_snd_ctrl_msg_correct(os_ctrl_cxn_id, 1) == 1 ?
					printf("CTRL:CORRECT\n") : printf("CTRL:WRONG\n");

	i = 2;
	time_ms = 4;
	while (i-- > 0) {
		printf("sleep ... %u\n", time_ms);
		sleep(time_ms);
		printf("sleep WAKEUP and check MS\n");
		is_fwd_packet_correct(lldpa->port_no, 0) == 1 ?
					printf("%d:CORRECT\n", i) : printf("%d:WRONG\n", i);
	}

	return ret;
}

int test_2_simple_RX_REQ(lldpa_port_t *lldpa)
{
	int i, ret = 0;
	octets_t *pkt = NULL;
	uint32_t time_ms = 0;

	/*1. Gen the RX Req Start packet */
	octets_buf_t *lldp_pdu = &Tx_Pkt_Q_Expected[lldpa->port_no-1];

	lldp_pdu->buf = (octets_t *)Lldppdu_Rx;
	lldp_pdu->len = sizeof(Lldppdu_Rx);

	time_ms = 4;
	printf("Send RX-REQ Start Message\n");
	pkt = gen_pkt(SW_CONTR_RX_REQ, time_ms, lldpa->port_no, lldp_pdu->buf, lldp_pdu->len);
	if (!pkt)
		return -1;

	lldpa_agent_handle_msg (lldpa, pkt);
	free(pkt);

	PKT.subtype = SW_CONTR_RX_RES;
	PKT.length = sizeof(PKT);
	PKT.interval_ms = time_ms;
	PKT.port_no     = lldpa->port_no;
	Tx_Ctrl_Msg_Q_Expected[lldpa->port_no-1].buf = (octets_t*)&PKT;
	Tx_Ctrl_Msg_Q_Expected[lldpa->port_no-1].len = sizeof(PKT);
	is_snd_ctrl_msg_correct(os_ctrl_cxn_id, 1) == 1 ?
					printf("CTRL:CORRECT\n") : printf("CTRL:WRONG\n");

	lldpa->rx_pkt_matched == 0 ?
			        printf("RX_EXPECTED 0: CORRECT\n") : printf("RX_EXPECTED 0: WRONG\n");
	/*2. Will expect RX packet every interval
	 *   Do it 2 times
	 */
	i =2;
	time_ms = 4;
	while (i-- > 0) {
		lldpa_agent_handle_pkt (lldpa, lldp_pdu->buf, lldp_pdu->len);
		lldpa->rx_pkt_matched == 1 ?
					        printf("RX_EXPECTED 1: CORRECT\n") : printf("RX_EXPECTED 1: WRONG\n");
		printf("sleep ... %u\n", time_ms);
		sleep(time_ms);
		printf("sleep WAKEUP and check\n");
		lldpa->rx_pkt_matched == 0 ?
					        printf("RX_EXPECTED 0: CORRECT\n") : printf("RX_EXPECTED 0: WRONG\n");
	}

	/*3. Test timeout
	 *   Control will expect TIMEOUT PACKET*/
	i = 2;
	time_ms = 4;
	while (i-- > 0) {
		printf("sleep ... for timeout %u\n", time_ms);
		sleep(time_ms);
		printf("sleep WAKEUP and check TIMEOUT MSG\n");
		lldpa->rx_pkt_matched == 0 ?
							printf("RX_EXPECTED 0: CORRECT\n") : printf("RX_EXPECTED 0: WRONG\n");
		PKT.subtype = LLDPA_CONTR_STYPE_TIMEOUT;
		PKT.length = sizeof(PKT);
		PKT.interval_ms = 0;
		PKT.port_no     = lldpa->port_no;
		Tx_Ctrl_Msg_Q_Expected[lldpa->port_no-1].buf = (octets_t*)&PKT;
		Tx_Ctrl_Msg_Q_Expected[lldpa->port_no-1].len = sizeof(PKT);
		is_snd_ctrl_msg_correct(os_ctrl_cxn_id, 1) == 1 ?
						printf("CTRL:TIMEOUT CORRECT\n") : printf("CTRL:TIMEOUT WRONG\n");
	}

	/*4. Gen the TX Req Stop packet */
	sleep(2);
	time_ms = 0;
	pkt = gen_pkt(SW_CONTR_RX_REQ, time_ms, lldpa->port_no, NULL , 0);
	if (!pkt)
		return -1;

	printf("Send RX-REQ Stop NULL Message\n");
	lldpa_agent_handle_msg (lldpa, pkt);
	free(pkt);

	PKT.subtype = SW_CONTR_RX_RES;
	PKT.length = sizeof(PKT);
	PKT.interval_ms = time_ms;
	PKT.port_no     = lldpa->port_no;
	Tx_Ctrl_Msg_Q_Expected[lldpa->port_no-1].buf = (octets_t*)&PKT;
	Tx_Ctrl_Msg_Q_Expected[lldpa->port_no-1].len = sizeof(PKT);
	is_snd_ctrl_msg_correct(os_ctrl_cxn_id, 1) == 1 ?
					printf("CTRL:CORRECT\n") : printf("CTRL:WRONG\n");


	/*5. Receive Unexpected Msg - Sent to controller */
	lldpa_agent_handle_pkt (lldpa, lldp_pdu->buf, lldp_pdu->len);
	PKT_IN.hdr = PKT;
	PKT_IN.hdr.subtype = SW_CONTR_PACKET_IN;
	PKT_IN.hdr.length = sizeof(PKT_IN);
	PKT_IN.hdr.interval_ms = 0;
	PKT_IN.hdr.port_no     = lldpa->port_no;
	Tx_Ctrl_Msg_Q_Expected[lldpa->port_no-1].buf = (octets_t*)&PKT_IN;
	Tx_Ctrl_Msg_Q_Expected[lldpa->port_no-1].len = sizeof(PKT_IN);
	is_snd_ctrl_msg_correct(os_ctrl_cxn_id, 1) == 1 ?
					printf("CTRL: RX CORRECT\n") : printf("CTRL: RX WRONG\n");

	return ret;
}

int aim_main(int argc, char* argv[])
{
	int i = 0;
	int port_id;
    printf("lldpa Utest Start ..\n");
    lldpa_config_show(&aim_pvs_stdout);

#ifdef USE_OS_ALARM
    printf("Setup alarm_register\n");
    os_alarm_register_fn = &os_alarm_register;
    os_alarm_unregister_fn = &os_alarm_unregister;
#endif

    os_ctrl_cxn_id = CTRLID;

    printf("lldpa Utest Create %d Ports  ..\n", NUMPORT);
    /*1. Create lldpa_port with lldpa_port_rx_check and lldpa_port_tx callback */
    for (i = 0; i < NUMPORT;i++) {
    	port_id = i+1;
    	PortList[i] = lldpa_port_create(port_id);
    	lldpa_port_set_fwd_pkt_fn(PortList[i], os_fwd_pkt_out);
    	lldpa_port_set_snd_ctrl_msg_fn(PortList[i], os_send_ctrl_msg);
    }

    /*2. Test */
    for (i = 0; i < NUMPORT;i++) {
    	//test_1_simple_TX_REQ(PortList[i]);
    	//test_2_simple_RX_REQ(PortList[i]);
    }

    return 0;
}

