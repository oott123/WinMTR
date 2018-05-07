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

/*unsigned long getValue( 获取文件中指定的16进制串的值，并返回
FILE *fp, 指定文件指针
unsigned long start, 指定文件偏移量
int length) 获取的16进制字符个数/长度
*/
unsigned long getValue(FILE *fp, unsigned long start, int length)
{
    unsigned long variable = 0;
    long val[255], i;

    fseek(fp, start, SEEK_SET);
    for (i = 0; i<length; i++)
    {
        /*过滤高位，一次读取一个字符*/
        val[i] = fgetc(fp) & 0x000000FF;
    }
    for (i = length - 1; i >= 0; i--)
    {
        /*因为读取多个16进制字符，叠加*/
        variable = variable * 0x100 + val[i];
    }
    return variable;
};


/*int getString( 获取文件中指定的字符串，返回字符串长度
FILE *fp, 指定文件指针
unsigned long start, 指定文件偏移量
char **string) 用来存放将读取字符串的字符串空间的首地址
*/
int getString(FILE *fp, unsigned long start, char *string)
{
    unsigned long i = 0;
    char val;
    fseek(fp, start, SEEK_SET);
    /*读取字符串，直到遇到0x00为止*/
    do
    {
        val = fgetc(fp);
        /*依次放入用来存储的字符串空间中*/
        string[i++] = val;
    } while (val != 0x00);
    /*返回字符串长度*/
    return i;
};


/*void getAddress( 读取指定IP的国家位置和地域位置
FILE *fp, 指定文件指针
unsigned long start, 指定IP在索引中的文件偏移量
char **country, 用来存放国家位置的字符串空间的首地址
char **location) 用来存放地域位置的字符串空间的首地址
*/
void getAddress(FILE *fp, unsigned long start, char *country, char *location)
{
    unsigned long redirect_address, counrty_address, location_address;
    char val;

    start += 4;
    fseek(fp, start, SEEK_SET);
    /*读取首地址的值*/
    val = (fgetc(fp) & 0x000000FF);

    if (val == REDIRECT_MODE_1)
    {
        /*重定向1类型的*/
        redirect_address = getValue(fp, start + 1, 3);
        fseek(fp, redirect_address, SEEK_SET);
        /*混合类型，重定向1类型进入后遇到重定向2类型
        读取重定向后的内容，并设置地域位置的文件偏移量*/
        if ((fgetc(fp) & 0x000000FF) == REDIRECT_MODE_2)
        {
            counrty_address = getValue(fp, redirect_address + 1, 3);
            location_address = redirect_address + 4;
            getString(fp, counrty_address, country);
        }
        /*读取重定向1后的内容，并设置地域位置的文件偏移量*/
        else
        {
            counrty_address = redirect_address;
            location_address = redirect_address + getString(fp, counrty_address, country);
        }
    }
    /*重定向2类型的*/
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

    /*读取地域位置*/
    fseek(fp, location_address, SEEK_SET);
    if ((fgetc(fp) & 0x000000FF) == REDIRECT_MODE_2 || (fgetc(fp) & 0x000000FF) == REDIRECT_MODE_1)
    {
        location_address = getValue(fp, location_address + 1, 3);
    }
    getString(fp, location_address, location);

    return;
};


/*void getHead( 读取索引部分的范围（在文件头中，最先的2个8位16进制）
FILE *fp, 指定文件指针
unsigned long *start, 文件偏移量，索引的起止位置
unsigned long *end) 文件偏移量，索引的结束位置
*/
void getHead(FILE *fp, unsigned long *start, unsigned long *end)
{
    /*索引的起止位置的文件偏移量，存储在文件头中的前8个16进制中
    设置偏移量为0，读取4个字符*/
    *start = getValue(fp, 0L, 4);
    /*索引的结束位置的文件偏移量，存储在文件头中的第8个到第15个的16进制中
    设置偏移量为4个字符，再读取4个字符*/
    *end = getValue(fp, 4L, 4);
};


/*unsigned long searchIP( 搜索指定IP在索引区的位置，采用二分查找法；
返回IP在索引区域的文件偏移量
一条索引记录的结果是，前4个16进制表示起始IP地址
后面3个16进制，表示该起始IP在IP信息段中的位置，文件偏移量
FILE *fp,
unsigned long index_start, 索引起始位置的文件偏移量
unsigned long index_end, 索引结束位置的文件偏移量
unsigned long ip) 关键字，要索引的IP
*/
unsigned long searchIP(FILE *fp, unsigned long index_start, \

    unsigned long index_end, unsigned long ip)
{
    unsigned long index_current, index_top, index_bottom;
    unsigned long record;
    index_bottom = index_start;
    index_top = index_end;
    /*此处的7，是因为一条索引记录的长度是7*/
    index_current = ((index_top - index_bottom) / 7 / 2) * 7 + index_bottom;
    /*二分查找法*/
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
    /*返回关键字IP在索引区域的文件偏移量*/
    return index_current;
};


/*unsigned long putAll( 导出所有IP信息到文件文件中，函数返回导出总条数
FILE *fp,
FILE *out, 导出的文件指针，必须拥有写权限
unsigned long index_start, 索引区域的起始文件偏移量
unsigned long index_end) 索引区域的结束文件偏移量
*/
unsigned long putAll(FILE *fp, FILE *out, unsigned long index_start, unsigned long index_end)
{
    unsigned long i, count = 0;
    unsigned long start_ip, end_ip;
    char country[MAXBUF];
    char location[MAXBUF];

    /*此处的7，是因为一条索引记录的长度是7*/
    for (i = index_start; i<index_end; i += 7)
    {
        /*获取IP段的起始IP和结束IP，
        起始IP为索引部分的前4位16进制
        结束IP在IP信息部分的前4位16进制中，靠索引部分指定的偏移量找寻*/
        start_ip = getValue(fp, i, 4);
        end_ip = getValue(fp, getValue(fp, i + 4, 3), 4);
        /*导出IP信息，格式是
        起始IP\t结束IP\t国家位置\t地域位置\n*/
        fprintf(out, "%d.%d.%d.%d", (start_ip & 0xFF000000) >> 0x18, \

            (start_ip & 0x00FF0000) >> 0x10, (start_ip & 0x0000FF00) >> 0x8, start_ip & 0x000000FF);
        fprintf(out, "\t");
        fprintf(out, "%d.%d.%d.%d", (end_ip & 0xFF000000) >> 0x18, \

            (end_ip & 0x00FF0000) >> 0x10, (end_ip & 0x0000FF00) >> 0x8, end_ip & 0x000000FF);
        getAddress(fp, getValue(fp, i + 4, 3), country, location);
        fprintf(out, "\t%s\t%s\n", country, location);
        count++;
    }
    /*返回导出总条数*/
    return count;
};


/*判断一个字符是否为数字字符，
如果是，返回0
如果不是，返回1*/
int beNumber(char c)
{
    if (c >= '0'&&c <= '9')
        return 0;
    else
        return 1;
};


/*函数的参数是一个存储着IP地址的字符串首地址
返回该IP的16进制代码
如果输入的IP地址有错误，函数将返回0*/
unsigned long getIP(char *ip_addr)
{
    unsigned long ip = 0;
    int i, j = 0;
    /*依次读取字符串中的各个字符*/
    for (i = 0; i<strlen(ip_addr); i++)
    {
        /*如果是IP地址间隔的‘.’符号
        把当前读取到的IP字段的值，存入ip变量中
        （注意，ip为叠加时，乘以16进制的0x100）
        并清除临时变量的值*/
        if (*(ip_addr + i) == '.')
        {
            ip = ip * 0x100 + j;
            j = 0;
        }
        /*往临时变量中写入当前读取到的IP字段中的字符值
        叠加乘以10，因为输入的IP地址是10进制*/
        else
        {
            /*判断，如果输入的IP地址不规范，不是10进制字符
            函数将返回0*/
            if (beNumber(*(ip_addr + i)) == 0)
                j = j * 10 + *(ip_addr + i) - '0';
            else
                return 0;
        }
    }
    /*IP字段有4个，但是‘.’只有3个，叠加第四个字段值*/
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
		//搜索IP在索引区域的条目的偏移量
		current = searchIP(fp, index_start, index_end, addr);
		//获取该IP对因的国家地址和地域地址
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
