//*****************************************************************************
// FILE:            WinMTRNet.cpp
//
//*****************************************************************************
#include "WinMTRGlobal.h"
#include "WinMTRNet.h"
#include "WinMTRDialog.h"
#include <iostream>
#include <sstream>
#include <string>

#include "stdio.h"
#include "string.h"

#define QQWRY "QQWry.dat"
#define REDIRECT_MODE_1 0x01
#define REDIRECT_MODE_2 0x02
#define MAXBUF 255


#define TRACE_MSG(msg)										\
	{														\
	std::ostringstream dbg_msg(std::ostringstream::out);	\
	dbg_msg << msg << std::endl;							\
	OutputDebugString(dbg_msg.str().c_str());				\
	}

#define IPFLAG_DONT_FRAGMENT	0x02
#define MAX_HOPS				30

struct trace_thread {
	int			address;
	WinMTRNet	*winmtr;
	int			ttl;
};

struct dns_resolver_thread {
	int			index;
	WinMTRNet	*winmtr;
};

void TraceThread(void *p);
void DnsResolverThread(void *p);

WinMTRNet::WinMTRNet(WinMTRDialog *wp) {
	
	ghMutex = CreateMutex(NULL, FALSE, NULL);
	tracing=false;
	initialized = false;
	wmtrdlg = wp;
	WSADATA wsaData;

    if( WSAStartup(MAKEWORD(2, 2), &wsaData) ) {
        AfxMessageBox("Failed initializing windows sockets library!");
		return;
    }

    hICMP_DLL =  LoadLibrary(_T("ICMP.DLL"));
    if (hICMP_DLL == 0) {
        AfxMessageBox("Failed: Unable to locate ICMP.DLL!");
        return;
    }

    /* 
     * Get pointers to ICMP.DLL functions
     */
    lpfnIcmpCreateFile  = (LPFNICMPCREATEFILE)GetProcAddress(hICMP_DLL,"IcmpCreateFile");
    lpfnIcmpCloseHandle = (LPFNICMPCLOSEHANDLE)GetProcAddress(hICMP_DLL,"IcmpCloseHandle");
    lpfnIcmpSendEcho    = (LPFNICMPSENDECHO)GetProcAddress(hICMP_DLL,"IcmpSendEcho");
    if ((!lpfnIcmpCreateFile) || (!lpfnIcmpCloseHandle) || (!lpfnIcmpSendEcho)) {
        AfxMessageBox("Wrong ICMP.DLL system library !");
        return;
    }

    /*
     * IcmpCreateFile() - Open the ping service
     */
    hICMP = (HANDLE) lpfnIcmpCreateFile();
    if (hICMP == INVALID_HANDLE_VALUE) {
        AfxMessageBox("Error in ICMP.DLL !");
        return;
    }

	ResetHops();

	initialized = true;
	return;
}

WinMTRNet::~WinMTRNet()
{
	if(initialized) {
		/*
		 * IcmpCloseHandle - Close the ICMP handle
		 */
		lpfnIcmpCloseHandle(hICMP);

		// Shut down...
		FreeLibrary(hICMP_DLL);

		WSACleanup();
	
		CloseHandle(ghMutex);
	}
}

void WinMTRNet::ResetHops()
{
	for(int i = 0; i < MaxHost;i++) {
		host[i].addr = 0;
		host[i].xmit = 0;
		host[i].returned = 0;
		host[i].total = 0;
		host[i].last = 0;
		host[i].best = 0;
		host[i].worst = 0;
		memset(host[i].name,0,sizeof(host[i].name));
	}
}

void WinMTRNet::DoTrace(int address)
{
	HANDLE hThreads[MAX_HOPS];
	tracing = true;

	ResetHops();

	last_remote_addr = address;

	// one thread per TTL value
	for(int i = 0; i < MAX_HOPS; i++) {
		trace_thread *current = new trace_thread;
		current->address = address;
		current->winmtr = this;
		current->ttl = i + 1;
		hThreads[i] = (HANDLE)_beginthread(TraceThread, 0 , current);
	}

	WaitForMultipleObjects(MAX_HOPS, hThreads, TRUE, INFINITE);
}

void WinMTRNet::StopTrace()
{
	tracing = false;
}

void TraceThread(void *p)
{
	trace_thread* current = (trace_thread*)p;
	WinMTRNet *wmtrnet = current->winmtr;
	TRACE_MSG("Threaad with TTL=" << current->ttl << " started.");

    IPINFO			stIPInfo, *lpstIPInfo;
    DWORD			dwReplyCount;
	char			achReqData[8192];
	int				nDataLen									= wmtrnet->wmtrdlg->pingsize;
	char			achRepData[sizeof(ICMPECHO) + 8192];


    /*
     * Init IPInfo structure
     */
    lpstIPInfo				= &stIPInfo;
    stIPInfo.Ttl			= current->ttl;
    stIPInfo.Tos			= 0;
    stIPInfo.Flags			= IPFLAG_DONT_FRAGMENT;
    stIPInfo.OptionsSize	= 0;
    stIPInfo.OptionsData	= NULL;

    for (int i=0; i<nDataLen; i++) achReqData[i] = 32; //whitespaces

    while(wmtrnet->tracing) {
	    
		// For some strange reason, ICMP API is not filling the TTL for icmp echo reply
		// Check if the current thread should be closed
		if( current->ttl > wmtrnet->GetMax() ) break;

		// NOTE: some servers does not respond back everytime, if TTL expires in transit; e.g. :
		// ping -n 20 -w 5000 -l 64 -i 7 www.chinapost.com.tw  -> less that half of the replies are coming back from 219.80.240.93
		// but if we are pinging ping -n 20 -w 5000 -l 64 219.80.240.93  we have 0% loss
		// A resolution would be:
		// - as soon as we get a hop, we start pinging directly that hop, with a greater TTL
		// - a drawback would be that, some servers are configured to reply for TTL transit expire, but not to ping requests, so,
		// for these servers we'll have 100% loss
		dwReplyCount = wmtrnet->lpfnIcmpSendEcho(wmtrnet->hICMP, current->address, achReqData, nDataLen, lpstIPInfo, achRepData, sizeof(achRepData), ECHO_REPLY_TIMEOUT);

		PICMPECHO icmp_echo_reply = (PICMPECHO)achRepData;

		wmtrnet->AddXmit(current->ttl - 1);
		if (dwReplyCount != 0) {
			TRACE_MSG("TTL " << current->ttl << " reply TTL " << icmp_echo_reply->Options.Ttl << " Status " << icmp_echo_reply->Status << " Reply count " << dwReplyCount);

			switch(icmp_echo_reply->Status) {
				case IP_SUCCESS:
				case IP_TTL_EXPIRED_TRANSIT:
					wmtrnet->SetLast(current->ttl - 1, icmp_echo_reply->RoundTripTime);
					wmtrnet->SetBest(current->ttl - 1, icmp_echo_reply->RoundTripTime);
					wmtrnet->SetWorst(current->ttl - 1, icmp_echo_reply->RoundTripTime);
					wmtrnet->AddReturned(current->ttl - 1);
					wmtrnet->SetAddr(current->ttl - 1, icmp_echo_reply->Address);
				break;
				case IP_BUF_TOO_SMALL:
					wmtrnet->SetName(current->ttl - 1, "Reply buffer too small.");
				break;
				case IP_DEST_NET_UNREACHABLE:
					wmtrnet->SetName(current->ttl - 1, "Destination network unreachable.");
				break;
				case IP_DEST_HOST_UNREACHABLE:
					wmtrnet->SetName(current->ttl - 1, "Destination host unreachable.");
				break;
				case IP_DEST_PROT_UNREACHABLE:
					wmtrnet->SetName(current->ttl - 1, "Destination protocol unreachable.");
				break;
				case IP_DEST_PORT_UNREACHABLE:
					wmtrnet->SetName(current->ttl - 1, "Destination port unreachable.");
				break;
				case IP_NO_RESOURCES:
					wmtrnet->SetName(current->ttl - 1, "Insufficient IP resources were available.");
				break;
				case IP_BAD_OPTION:
					wmtrnet->SetName(current->ttl - 1, "Bad IP option was specified.");
				break;
				case IP_HW_ERROR:
					wmtrnet->SetName(current->ttl - 1, "Hardware error occurred.");
				break;
				case IP_PACKET_TOO_BIG:
					wmtrnet->SetName(current->ttl - 1, "Packet was too big.");
				break;
				case IP_REQ_TIMED_OUT:
					wmtrnet->SetName(current->ttl - 1, "Request timed out.");
				break;
				case IP_BAD_REQ:
					wmtrnet->SetName(current->ttl - 1, "Bad request.");
				break;
				case IP_BAD_ROUTE:
					wmtrnet->SetName(current->ttl - 1, "Bad route.");
				break;
				case IP_TTL_EXPIRED_REASSEM:
					wmtrnet->SetName(current->ttl - 1, "The time to live expired during fragment reassembly.");
				break;
				case IP_PARAM_PROBLEM:
					wmtrnet->SetName(current->ttl - 1, "Parameter problem.");
				break;
				case IP_SOURCE_QUENCH:
					wmtrnet->SetName(current->ttl - 1, "Datagrams are arriving too fast to be processed and datagrams may have been discarded.");
				break;
				case IP_OPTION_TOO_BIG:
					wmtrnet->SetName(current->ttl - 1, "An IP option was too big.");
				break;
				case IP_BAD_DESTINATION:
					wmtrnet->SetName(current->ttl - 1, "Bad destination.");
				break;
				case IP_GENERAL_FAILURE:
					wmtrnet->SetName(current->ttl - 1, "General failure.");
				break;
				default:
					wmtrnet->SetName(current->ttl - 1, "General failure.");
			}

			if(wmtrnet->wmtrdlg->interval * 1000 > icmp_echo_reply->RoundTripTime)
				Sleep(wmtrnet->wmtrdlg->interval * 1000 - icmp_echo_reply->RoundTripTime);
		}

    } /* end ping loop */

	TRACE_MSG("Thread with TTL=" << current->ttl << " stopped.");

	delete p;
	_endthread();
}

int WinMTRNet::GetAddr(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int addr = ntohl(host[at].addr);
	ReleaseMutex(ghMutex);
	return addr;
}

int WinMTRNet::GetName(int at, char *n)
{
	WaitForSingleObject(ghMutex, INFINITE);
	if(!strcmp(host[at].name, "")) {
		int addr = GetAddr(at);
		sprintf (	n, "%d.%d.%d.%d", 
							(addr >> 24) & 0xff, 
							(addr >> 16) & 0xff, 
							(addr >> 8) & 0xff, 
							addr & 0xff
		);
		if(addr==0)
			strcpy(n,"");
	} else {
		strcpy(n, host[at].name);
	}
	ReleaseMutex(ghMutex);
	return 0;
}

int WinMTRNet::GetBest(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].best;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetWorst(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].worst;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetAvg(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].returned == 0 ? 0 : host[at].total / host[at].returned;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetPercent(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = (host[at].xmit == 0) ? 0 : (100 - (100 * host[at].returned / host[at].xmit));
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetLast(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].last;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetReturned(int at)
{ 
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].returned;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetXmit(int at)
{ 
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].xmit;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetMax()
{
	WaitForSingleObject(ghMutex, INFINITE);
	int max = MAX_HOPS;

	// first match: traced address responds on ping requests, and the address is in the hosts list
	for(int i = 0; i < MAX_HOPS; i++) {
		if(host[i].addr == last_remote_addr) {
			max = i + 1;
			break;
		}
	}

	// second match:  traced address doesn't responds on ping requests
	if(max == MAX_HOPS) {
		while((max > 1) && (host[max - 1].addr == host[max - 2].addr) && (host[max - 1].addr != 0) ) max--;
	}

	ReleaseMutex(ghMutex);
	return max;
}

void WinMTRNet::SetAddr(int at, __int32 addr)
{
	WaitForSingleObject(ghMutex, INFINITE);
	if(host[at].addr == 0 && addr != 0) {
		TRACE_MSG("Start DnsResolverThread for new address " << addr << ". Old addr value was " << host[at].addr);
		host[at].addr = addr;
		dns_resolver_thread *dnt = new dns_resolver_thread;
		dnt->index = at;
		dnt->winmtr = this;
		if(wmtrdlg->useDNS) _beginthread(DnsResolverThread, 0, dnt);
	}

	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetName(int at, char *n)
{
	WaitForSingleObject(ghMutex, INFINITE);
	strcpy(host[at].name, n);
	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetBest(int at, int current)
{
	WaitForSingleObject(ghMutex, INFINITE);
	if(host[at].best > current || host[at].xmit == 1) {
		host[at].best = current;
	};
	if(host[at].worst < current) {
		host[at].worst = current;
	}

	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetWorst(int at, int current)
{
	WaitForSingleObject(ghMutex, INFINITE);
	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetLast(int at, int last)
{
	WaitForSingleObject(ghMutex, INFINITE);
	host[at].last = last;
	host[at].total += last;
	ReleaseMutex(ghMutex);
}

void WinMTRNet::AddReturned(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	host[at].returned++;
	ReleaseMutex(ghMutex);
}

void WinMTRNet::AddXmit(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	host[at].xmit++;
	ReleaseMutex(ghMutex);
}

/*unsigned long getValue( ��ȡ�ļ���ָ����16���ƴ���ֵ��������
FILE *fp, ָ���ļ�ָ��
unsigned long start, ָ���ļ�ƫ����
int length) ��ȡ��16�����ַ�����/����
*/
unsigned long getValue(FILE *fp, unsigned long start, int length)
{
    unsigned long variable = 0;
    long val[255], i;

    fseek(fp, start, SEEK_SET);
    for (i = 0; i<length; i++)
    {
        /*���˸�λ��һ�ζ�ȡһ���ַ�*/
        val[i] = fgetc(fp) & 0x000000FF;
    }
    for (i = length - 1; i >= 0; i--)
    {
        /*��Ϊ��ȡ���16�����ַ�������*/
        variable = variable * 0x100 + val[i];
    }
    return variable;
};


/*int getString( ��ȡ�ļ���ָ�����ַ����������ַ�������
FILE *fp, ָ���ļ�ָ��
unsigned long start, ָ���ļ�ƫ����
char **string) ������Ž���ȡ�ַ������ַ����ռ���׵�ַ
*/
int getString(FILE *fp, unsigned long start, char *string)
{
    unsigned long i = 0;
    char val;
    fseek(fp, start, SEEK_SET);
    /*��ȡ�ַ�����ֱ������0x00Ϊֹ*/
    do
    {
        val = fgetc(fp);
        /*���η��������洢���ַ����ռ���*/
        string[i++] = val;
    } while (val != 0x00);
    /*�����ַ�������*/
    return i;
};


/*void getAddress( ��ȡָ��IP�Ĺ���λ�ú͵���λ��
FILE *fp, ָ���ļ�ָ��
unsigned long start, ָ��IP�������е��ļ�ƫ����
char **country, ������Ź���λ�õ��ַ����ռ���׵�ַ
char **location) ������ŵ���λ�õ��ַ����ռ���׵�ַ
*/
void getAddress(FILE *fp, unsigned long start, char *country, char *location)
{
    unsigned long redirect_address, counrty_address, location_address;
    char val;

    start += 4;
    fseek(fp, start, SEEK_SET);
    /*��ȡ�׵�ַ��ֵ*/
    val = (fgetc(fp) & 0x000000FF);

    if (val == REDIRECT_MODE_1)
    {
        /*�ض���1���͵�*/
        redirect_address = getValue(fp, start + 1, 3);
        fseek(fp, redirect_address, SEEK_SET);
        /*������ͣ��ض���1���ͽ���������ض���2����
        ��ȡ�ض��������ݣ������õ���λ�õ��ļ�ƫ����*/
        if ((fgetc(fp) & 0x000000FF) == REDIRECT_MODE_2)
        {
            counrty_address = getValue(fp, redirect_address + 1, 3);
            location_address = redirect_address + 4;
            getString(fp, counrty_address, country);
        }
        /*��ȡ�ض���1������ݣ������õ���λ�õ��ļ�ƫ����*/
        else
        {
            counrty_address = redirect_address;
            location_address = redirect_address + getString(fp, counrty_address, country);
        }
    }
    /*�ض���2���͵�*/
    else if (val == REDIRECT_MODE_2)
    {
        counrty_address = getValue(fp, start + 1, 3);
        location_address = start + 4;
        getString(fp, counrty_address, country);
    }
    else
    {
        counrty_address = start;
        location_address = counrty_address + getString(fp, counrty_address, country);
    }

    /*��ȡ����λ��*/
    fseek(fp, location_address, SEEK_SET);
    if ((fgetc(fp) & 0x000000FF) == REDIRECT_MODE_2 || (fgetc(fp) & 0x000000FF) == REDIRECT_MODE_1)
    {
        location_address = getValue(fp, location_address + 1, 3);
    }
    getString(fp, location_address, location);

    return;
};


/*void getHead( ��ȡ�������ֵķ�Χ�����ļ�ͷ�У����ȵ�2��8λ16���ƣ�
FILE *fp, ָ���ļ�ָ��
unsigned long *start, �ļ�ƫ��������������ֹλ��
unsigned long *end) �ļ�ƫ�����������Ľ���λ��
*/
void getHead(FILE *fp, unsigned long *start, unsigned long *end)
{
    /*��������ֹλ�õ��ļ�ƫ�������洢���ļ�ͷ�е�ǰ8��16������
    ����ƫ����Ϊ0����ȡ4���ַ�*/
    *start = getValue(fp, 0L, 4);
    /*�����Ľ���λ�õ��ļ�ƫ�������洢���ļ�ͷ�еĵ�8������15����16������
    ����ƫ����Ϊ4���ַ����ٶ�ȡ4���ַ�*/
    *end = getValue(fp, 4L, 4);
};


/*unsigned long searchIP( ����ָ��IP����������λ�ã����ö��ֲ��ҷ���
����IP������������ļ�ƫ����
һ��������¼�Ľ���ǣ�ǰ4��16���Ʊ�ʾ��ʼIP��ַ
����3��16���ƣ���ʾ����ʼIP��IP��Ϣ���е�λ�ã��ļ�ƫ����
FILE *fp,
unsigned long index_start, ������ʼλ�õ��ļ�ƫ����
unsigned long index_end, ��������λ�õ��ļ�ƫ����
unsigned long ip) �ؼ��֣�Ҫ������IP
*/
unsigned long searchIP(FILE *fp, unsigned long index_start, \

    unsigned long index_end, unsigned long ip)
{
    unsigned long index_current, index_top, index_bottom;
    unsigned long record;
    index_bottom = index_start;
    index_top = index_end;
    /*�˴���7������Ϊһ��������¼�ĳ�����7*/
    index_current = ((index_top - index_bottom) / 7 / 2) * 7 + index_bottom;
    /*���ֲ��ҷ�*/
    do{
        record = getValue(fp, index_current, 4);
        if (record>ip)
        {
            index_top = index_current;
            index_current = ((index_top - index_bottom) / 14) * 7 + index_bottom;
        }
        else
        {
            index_bottom = index_current;
            index_current = ((index_top - index_bottom) / 14) * 7 + index_bottom;
        }
    } while (index_bottom<index_current);
    /*���عؼ���IP������������ļ�ƫ����*/
    return index_current;
};


/*unsigned long putAll( ��������IP��Ϣ���ļ��ļ��У��������ص���������
FILE *fp,
FILE *out, �������ļ�ָ�룬����ӵ��дȨ��
unsigned long index_start, �����������ʼ�ļ�ƫ����
unsigned long index_end) ��������Ľ����ļ�ƫ����
*/
unsigned long putAll(FILE *fp, FILE *out, unsigned long index_start, unsigned long index_end)
{
    unsigned long i, count = 0;
    unsigned long start_ip, end_ip;
    char country[MAXBUF];
    char location[MAXBUF];

    /*�˴���7������Ϊһ��������¼�ĳ�����7*/
    for (i = index_start; i<index_end; i += 7)
    {
        /*��ȡIP�ε���ʼIP�ͽ���IP��
        ��ʼIPΪ�������ֵ�ǰ4λ16����
        ����IP��IP��Ϣ���ֵ�ǰ4λ16�����У�����������ָ����ƫ������Ѱ*/
        start_ip = getValue(fp, i, 4);
        end_ip = getValue(fp, getValue(fp, i + 4, 3), 4);
        /*����IP��Ϣ����ʽ��
        ��ʼIP\t����IP\t����λ��\t����λ��\n*/
        fprintf(out, "%d.%d.%d.%d", (start_ip & 0xFF000000) >> 0x18, \

            (start_ip & 0x00FF0000) >> 0x10, (start_ip & 0x0000FF00) >> 0x8, start_ip & 0x000000FF);
        fprintf(out, "\t");
        fprintf(out, "%d.%d.%d.%d", (end_ip & 0xFF000000) >> 0x18, \

            (end_ip & 0x00FF0000) >> 0x10, (end_ip & 0x0000FF00) >> 0x8, end_ip & 0x000000FF);
        getAddress(fp, getValue(fp, i + 4, 3), country, location);
        fprintf(out, "\t%s\t%s\n", country, location);
        count++;
    }
    /*���ص���������*/
    return count;
};


/*�ж�һ���ַ��Ƿ�Ϊ�����ַ���
����ǣ�����0
������ǣ�����1*/
int beNumber(char c)
{
    if (c >= '0'&&c <= '9')
        return 0;
    else
        return 1;
};


/*�����Ĳ�����һ���洢��IP��ַ���ַ����׵�ַ
���ظ�IP��16���ƴ���
��������IP��ַ�д��󣬺���������0*/
unsigned long getIP(char *ip_addr)
{
    unsigned long ip = 0;
    int i, j = 0;
    /*���ζ�ȡ�ַ����еĸ����ַ�*/
    for (i = 0; i<strlen(ip_addr); i++)
    {
        /*�����IP��ַ����ġ�.������
        �ѵ�ǰ��ȡ����IP�ֶε�ֵ������ip������
        ��ע�⣬ipΪ����ʱ������16���Ƶ�0x100��
        �������ʱ������ֵ*/
        if (*(ip_addr + i) == '.')
        {
            ip = ip * 0x100 + j;
            j = 0;
        }
        /*����ʱ������д�뵱ǰ��ȡ����IP�ֶ��е��ַ�ֵ
        ���ӳ���10����Ϊ�����IP��ַ��10����*/
        else
        {
            /*�жϣ���������IP��ַ���淶������10�����ַ�
            ����������0*/
            if (beNumber(*(ip_addr + i)) == 0)
                j = j * 10 + *(ip_addr + i) - '0';
            else
                return 0;
        }
    }
    /*IP�ֶ���4�������ǡ�.��ֻ��3�������ӵ��ĸ��ֶ�ֵ*/
    ip = ip * 0x100 + j;
    return ip;
};


void DnsResolverThread(void *p)
{
    TRACE_MSG("DNS resolver thread started.");
    dns_resolver_thread *dnt = (dns_resolver_thread*)p;
    WinMTRNet* wn = dnt->winmtr;

    struct hostent *phent;

    char buf[100];
    int addr = wn->GetAddr(dnt->index);
    sprintf(buf, "%d.%d.%d.%d", (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);

    int haddr = htonl(addr);
    //phent = gethostbyaddr( (const char*)&haddr, sizeof(int), AF_INET);
    FILE *fp;
    unsigned long index_start, index_end, current;
	char country[MAXBUF] = {0};
	char location[MAXBUF] = {0};
    fp = fopen(QQWRY, "rb");
	if (fp) {
		getHead(fp, &index_start, &index_end);
		getAddress(fp, getValue(fp, index_end + 4, 3), country, location);
		//����IP�������������Ŀ��ƫ����
		current = searchIP(fp, index_start, index_end, addr);
		//��ȡ��IP����Ĺ��ҵ�ַ�͵����ַ
		getAddress(fp, getValue(fp, current + 4, 3), country, location);
		fclose(fp);
	}
    std::string l = std::string(location);
    std::string c = std::string(country);
    std::string h;
    std::string blank = std::string(" ");
    std::string ipaddr = std::string(buf);
    h = ipaddr + blank + c + blank + l;
    char * writable = new char[h.size() + 1];
    std::copy(h.begin(), h.end(), writable);
    writable[h.size()] = '\0';
    wn->SetName(dnt->index, writable);
    delete p;
    TRACE_MSG("DNS resolver thread stopped.");
    _endthread();
}
