
// SimpleRouterDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "SimpleRouter.h"
#include "SimpleRouterDlg.h"
#include "afxdialogex.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif

struct RouterEntry
{
	DWORD mask;
	DWORD ip;
	DWORD next;
	bool isDirect; //��ֱ��Ͷ�ݵı���
};

struct IPMACEntry
{
	DWORD ip;
	BYTE mac[6];
};

struct DataBuf
{
	const u_char* pkt_data;
	const u_char* old_pkt_data;
	int len;
	int timerid;
	int timeleft;
	DWORD arpdstip;
	DWORD arpsrcip;
	DWORD errmsgip;
	int pkt_no;
};

vector<RouterEntry*> routerTable;
vector<IPMACEntry*> ipmacTable;
vector<DataBuf*> buffer; //·��������
int timerid = 1;
int pkt_no = 0;

#pragma pack(1)	 //ǿ�ƽ��ṹ��������������
struct FrameHeader_t  //��̫��֡�ײ�
{
	BYTE DesMAC[6];	 //Ŀ��MAC��ַ
	BYTE SrcMAC[6];	 //ԴMAC��ַ
	WORD FrameType;	 //֡����
};

struct IPHeader_t	//IP�ײ�
{
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	ULONG SrcIP;
	ULONG DstIP;
};

struct Data_t	//����֡�ײ���IP�ײ������ݰ�
{
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
};

struct ICMP_t	//����֡�ײ���IP�ײ���ICMP���ݰ�
{
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	BYTE Type;
	BYTE Code;
	WORD Checksum;
	WORD ID;
	WORD Seq;
	BYTE Data[1];//���ȿɱ������
};

struct ARPFrame_t  //ARP֡
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
};
#pragma pack()

/* From tcptraceroute, convert a numeric IP address to a string */
char *iptos(u_long in)
{
	char *output = new char[40];
	u_char *p;
	p = (u_char *)&in;
	sprintf(output, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output;
}

/* From tcptraceroute, convert a numeric MAC address to a string */
char *mactos(BYTE *in)
{
	char *output = new char[40];
	sprintf(output, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", in[0], in[1], in[2], in[3], in[4], in[5]);
	return output;
}

bool macBroadcast(BYTE *in)	//MAC��ַ�Ƿ��ǹ㲥��ַ
{
	for (int i = 0; i < 6; i++)
	{
		if (in[i] != 0xff)
			return false;
	}
	return true;
}

CString char2CString(char *str)
{
	//����char *�����С�����ֽ�Ϊ��λ��һ������ռ�����ֽ�
	int charLen = strlen(str);
	//������ֽ��ַ��Ĵ�С�����ַ����㡣
	int len = MultiByteToWideChar(CP_ACP, 0, str, charLen, NULL, 0);
	//Ϊ���ֽ��ַ���������ռ䣬�����СΪ���ֽڼ���Ķ��ֽ��ַ���С
	TCHAR *buf = new TCHAR[len + 1];
	//���ֽڱ���ת���ɿ��ֽڱ���
	MultiByteToWideChar(CP_ACP, 0, str, charLen, buf, len);
	buf[len] = '\0';  //����ַ�����β��ע�ⲻ��len+1
	//��TCHAR����ת��ΪCString
	CString pWideChar;
	pWideChar.Append(buf);
	//ɾ��������
	delete[]buf;
	return pWideChar;
}

char *CString2char(CString str)
{
	//ע�⣺����n��len��ֵ��С��ͬ,n�ǰ��ַ�����ģ�len�ǰ��ֽڼ����
	int n = str.GetLength();
	//��ȡ���ֽ��ַ��Ĵ�С����С�ǰ��ֽڼ����
	int len = WideCharToMultiByte(CP_ACP, 0, str, str.GetLength(), NULL, 0, NULL, NULL);
	//Ϊ���ֽ��ַ���������ռ䣬�����СΪ���ֽڼ���Ŀ��ֽ��ֽڴ�С
	char * p = new char[len + 1];  //���ֽ�Ϊ��λ
	//���ֽڱ���ת���ɶ��ֽڱ���
	WideCharToMultiByte(CP_ACP, 0, str, str.GetLength(), p, len, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, str, str.GetLength() + 1, p, len + 1, NULL, NULL);
	p[len + 1] = '/0';  //���ֽ��ַ���'/0'����
	return p;
}

/* ͷ��У�� */
WORD checkSum(const u_char *src, int zero, int len)
{
	//CSimpleRouterDlg *pDlg = (CSimpleRouterDlg*)AfxGetApp()->GetMainWnd();
	//CString strlog, tt;
	//����ļӷ����޷��żӷ��������unsigned short��WORD��
	WORD result = ntohs(*((WORD *)src));
	//strlog.Format(L"0x%.4x ", result);
	//pDlg->m_log.InsertString(pDlg->m_log.GetCount(), strlog);
	for (int i = 2; i < len; i += 2)
	{
		WORD oldResult = result;
		WORD temp;
		if (i == zero) //У���ֶ���0
		{
			temp = 0;
		}
		else
		{
			temp = ntohs(*((WORD *)&src[i]));
		}
		//tt.Format(L"0x%.4x ",temp);
		//strlog += tt;
		result += temp;
		//�з���������ж�
		//���ж��������ķ����Ƿ�һ��
		//���һ�£���ֱ�Ƚ����������ͽ���ķ���λ������������෴���෴���ȽϽ��<0�������
		//�⼴������ͬ���ŵ�����ӱ��
		/*if ((oldResult ^ temp >= 0) && (result ^ oldResult) < 0 && (result ^ temp) < 0)
		{
		result += 1;
		} */
		//�޷���������������λ��ֻ�迴����Ƿ�С��ĳһ����������
		if (result < oldResult || result < temp)
		{
			result += 1;
		}
	}
	//result = ntohs(~result);
	result = ~result;
	//pDlg->m_log.InsertString(pDlg->m_log.GetCount(), strlog);
	//strlog.Format(L"last: 0x%.4x", result);
	//pDlg->m_log.InsertString(pDlg->m_log.GetCount(), strlog);
	return (WORD)result;
}

void sendARPpkt(BYTE *SrcMAC, BYTE *DstMAC, DWORD SrcIP, DWORD DstIP, WORD ope)
{
	CSimpleRouterDlg *pDlg = (CSimpleRouterDlg*)AfxGetApp()->GetMainWnd();
	CString ip;
	ARPFrame_t *ARPFrame = new ARPFrame_t;
	ARPFrame->FrameHeader.FrameType = htons(0x0806);	//֡����ΪARP
	ARPFrame->HardwareType = htons(0x0001);		//Ӳ������Ϊ��̫��
	ARPFrame->ProtocolType = htons(0x0800);		//Э������ΪIP
	ARPFrame->HLen = 6;							//Ӳ����ַ����Ϊ6
	ARPFrame->PLen = 4;							//Э���ַ����Ϊ4
	ARPFrame->Operation = htons(ope);
	bool broadcast = macBroadcast(DstMAC);
	for (int i = 0; i < 6; i++)
	{
		ARPFrame->FrameHeader.DesMAC[i] = DstMAC[i];
		if (broadcast)
		{
			ARPFrame->RecvHa[i] = 0x00;
		}
		else
		{
			ARPFrame->RecvHa[i] = DstMAC[i];
		}
		ARPFrame->FrameHeader.SrcMAC[i] = SrcMAC[i];
		ARPFrame->SendHa[i] = SrcMAC[i];
	}
	ARPFrame->SendIP = SrcIP;
	ARPFrame->RecvIP = DstIP;

	if (pcap_sendpacket(pDlg->adhandle, (const u_char*)ARPFrame,
		sizeof(ARPFrame_t)) != 0)
	{
		//���ʹ�����
		CString error;
		error.Format(L"Error sending the packet: %s", pcap_geterr(pDlg->adhandle));
		AfxMessageBox(error);
		return;
	}
	return;
}

void sendICMPpkt(const u_char *pkt_data, int len, BYTE Type, BYTE Code, BYTE *srcmac, DWORD srcip)
{
	CSimpleRouterDlg *pDlg = (CSimpleRouterDlg*)AfxGetApp()->GetMainWnd();
	static WORD idgen = rand() % 65536;	 //����IP���ݱ���ID
	ICMP_t *oldpkt = (ICMP_t*)pkt_data;
	ICMP_t *newpkt = NULL;
	int truelen;   //���ݲ���ʵ�ʳ���

	CString strlog;

	if (Type == 0x08 && Code == 0x00) //��������
	{
		truelen = len - sizeof(Data_t);//���������ݳ����Ǽ�ȥ��̫��֡ͷ��IP��ͷ����
		newpkt = (ICMP_t*)malloc(len);
		::memcpy((void*)newpkt, pkt_data, len);
		for (int i = 0; i < 6; i++)	//swap dst and src
		{
			newpkt->FrameHeader.DesMAC[i] = oldpkt->FrameHeader.SrcMAC[i];
			newpkt->FrameHeader.SrcMAC[i] = srcmac[i];
		}
		newpkt->IPHeader.SrcIP = srcip;
		newpkt->IPHeader.DstIP = oldpkt->IPHeader.SrcIP;
		newpkt->Type = 0x00;
		newpkt->IPHeader.TTL = 0x80;
		//���¼���У���
		newpkt->Checksum = htons(checkSum((const u_char*)&(newpkt->Type), 2, truelen));
		newpkt->IPHeader.Checksum = htons(checkSum((const u_char*)&(newpkt->IPHeader), 10, 20));
	}
	else
	{
		truelen = 36;//���ݲ���ǰ8�ֽ�
		newpkt = (ICMP_t*)malloc(sizeof(Data_t) + truelen);
		for (int i = 0; i < 6; i++)
		{
			newpkt->FrameHeader.DesMAC[i] = oldpkt->FrameHeader.SrcMAC[i];
			newpkt->FrameHeader.SrcMAC[i] = srcmac[i];
		}
		newpkt->FrameHeader.FrameType = htons(0x0800);
		newpkt->IPHeader.Ver_HLen = 0x45;//IP�ײ�һ����20�ֽ�
		newpkt->IPHeader.TOS = 0x00;
		newpkt->IPHeader.TotalLen = htons(0x0038);
		newpkt->IPHeader.ID = htons(++idgen);
		while (idgen == ntohs(oldpkt->IPHeader.ID))
		{
			newpkt->IPHeader.ID = htons(++idgen);
		}
		newpkt->IPHeader.Flag_Segment = 0x0000;
		newpkt->IPHeader.TTL = 0xff;
		newpkt->IPHeader.Protocol = 0x01;
		newpkt->IPHeader.Checksum = 0x0000;
		newpkt->IPHeader.SrcIP = srcip;
		newpkt->IPHeader.DstIP = oldpkt->IPHeader.SrcIP;
		newpkt->Type = Type;
		newpkt->Code = Code;
		newpkt->Checksum = 0x0000;
		newpkt->ID = 0x0000;
		newpkt->Seq = 0x0000;
		::memcpy((void*)&(newpkt->Data), &(oldpkt->IPHeader), truelen);
		//���¼���У���
		newpkt->Checksum = htons(checkSum((const u_char*)&(newpkt->Type), 2, truelen));
		newpkt->IPHeader.Checksum = htons(checkSum((const u_char*)&(newpkt->IPHeader), 10, 20));
	}

	if (pcap_sendpacket(pDlg->adhandle, (const u_char*)newpkt,
		sizeof(Data_t)+truelen) != 0)
	{
		//���ʹ�����
		CString error;
		error.Format(L"Error sending the packet: %s", pcap_geterr(pDlg->adhandle));
		AfxMessageBox(error);
		return;
	}
}


void pcap_handle(u_char *user, const pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	CSimpleRouterDlg *pDlg = (CSimpleRouterDlg*)AfxGetApp()->GetMainWnd();
	if (pDlg->isStopped)
		return;
	pDlg->PostMessageW(WM_PACKET, (WPARAM)pkt_header, (LPARAM)pkt_data);
}

UINT capturer(LPVOID hWnd)
{
	int res;
	pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	CSimpleRouterDlg *pDlg = (CSimpleRouterDlg*)AfxGetApp()->GetMainWnd();
	struct bpf_program fcode;
	char *filter = new char[100];
	sprintf(filter, "(ether src not %s) and (ether dst %s or ether broadcast) and (arp or ip)", 
		mactos(pDlg->mac), mactos(pDlg->mac), mactos(pDlg->mac));
	//compile the filter
	if (pcap_compile(pDlg->adhandle, &fcode, filter, 1, pDlg->masklist[0]) < 0)
	{
		CString error;
		error.Format(L"Error compiling filter: wrong syntax.");
		AfxMessageBox(error);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(pDlg->adhandle, &fcode)<0)
	{
		CString error;
		error.Format(L"Error setting the filter.");
		AfxMessageBox(error);
		return -1;
	}
	//��֪��Ϊʲô����pcap_next_ex���񵽰��ĳ���������
	/*while ((res = pcap_next_ex(pDlg->adhandle, &pkt_header, &pkt_data)) >= 0&&!pDlg->isStopped)
	{
	if (res == 0)
	{
	//pDlg->m_packetList.InsertString(pDlg->m_packetList.GetCount(), L"Capture timeout!");
	continue;
	}
	pDlg->PostMessageW(WM_PACKET, (WPARAM)pkt_header, (LPARAM)pkt_data);
	} */

	while (res = pcap_dispatch(pDlg->adhandle, 0, pcap_handle, NULL) >= 0)
	{
		if (pDlg->isStopped)
			break;
		//pcap_loop(pDlg->adhandle, -1, pcap_handle, NULL);
	}
	//{
	//pcap_loop(pDlg->adhandle, -1, pcap_handle, NULL);  //-1��ʾ����ѭ��ץȡ
	//pDlg->PostMessageW(WM_PACKET, (WPARAM)pkt_header, (LPARAM)pkt_data);
	//}

	if (res == -1 && !pDlg->isStopped)
	{
		CString error, temp;
		temp = char2CString(pcap_geterr(pDlg->adhandle));
		error.Format(L"Error reading the packets : %s\n", temp);
		AfxMessageBox(error);
		return -1;
	}

	pcap_close(pDlg->adhandle);
	return 0;
}

// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CSimpleRouterDlg �Ի���



CSimpleRouterDlg::CSimpleRouterDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_SIMPLEROUTER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDI_SMILE);
}

void CSimpleRouterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_INTERF, m_interf);
	DDX_Control(pDX, IDC_LOG, m_log);
	DDX_Control(pDX, IDC_TABLE, m_table);
	DDX_Control(pDX, IDC_MASK, m_mask);
	DDX_Control(pDX, IDC_DEST, m_dest);
	DDX_Control(pDX, IDC_NEXT, m_next);
	DDX_Control(pDX, IDC_START, m_start);
	DDX_Control(pDX, IDC_STOP, m_stop);
	DDX_Control(pDX, IDC_ADD, m_add);
	DDX_Control(pDX, IDC_DELE, m_dele);
	DDX_Control(pDX, IDC_CLEAR, m_clear);
}

BEGIN_MESSAGE_MAP(CSimpleRouterDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_MESSAGE(WM_PACKET, OnPacket)
	ON_CBN_SELCHANGE(IDC_INTERF, &CSimpleRouterDlg::OnCbnSelchangeInterf)
	ON_BN_CLICKED(IDC_ADD, &CSimpleRouterDlg::OnBnClickedAdd)
	ON_BN_CLICKED(IDC_DELE, &CSimpleRouterDlg::OnBnClickedDele)
	ON_BN_CLICKED(IDC_START, &CSimpleRouterDlg::OnBnClickedStart)
	ON_BN_CLICKED(IDC_STOP, &CSimpleRouterDlg::OnBnClickedStop)
	ON_WM_CLOSE()
	ON_WM_TIMER()
	ON_BN_CLICKED(IDC_CLEAR, &CSimpleRouterDlg::OnBnClickedClear)
END_MESSAGE_MAP()


// CSimpleRouterDlg ��Ϣ�������

BOOL CSimpleRouterDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	m_start.EnableWindow(FALSE);
	m_stop.EnableWindow(FALSE);
	m_add.EnableWindow(FALSE);
	m_dele.EnableWindow(FALSE);

	pcap_if_t *d;
	pcap_addr_t *a;
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
	char errbuf2[PCAP_ERRBUF_SIZE];

	//��ñ����Ľӿ��б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		//������
		CString error, temp;
		temp = char2CString(errbuf);
		error = L"Error in pcap_findalldevs_ex: ";
		error += temp;
		AfxMessageBox(error);
		pcap_freealldevs(alldevs);
		return FALSE;
	}

	//��ʾ�ӿ��б�
	for (d = alldevs; d != NULL; d = d->next)
	{
		char *name = d->name;  //����d->name��ȡ������ӿ��豸������
		CString namestr;
		namestr = char2CString(name); //ʹ�ú���char2CString()��Ϊ�˽����������
		m_interf.InsertString(m_interf.GetCount(), namestr);
		devices++;
	}

	if (devices == 0)
	{
		AfxMessageBox(L"No interfaces found! Make sure WinPcap is installed.");
		return FALSE;
	}

	if (m_interf.GetCount())
	{
		sel = 0;
		m_interf.SetCurSel(0);
		CString strText;
		m_interf.GetLBText(0, strText);
		for (d = alldevs; d != NULL; d = d->next)
		{
			char *name = d->name;  //����d->name��ȡ������ӿ��豸������
			CString namestr = char2CString(name);  //ʹ�ú���char2CString()��Ϊ�˽����������
			if (namestr == strText)
			{
				char *description = d->description;	 //����d->description��ȡ������ӿ��豸��������Ϣ
				char *addr = NULL, *netmask = NULL, *broadaddr = NULL, *dstaddr = NULL;
				CString addrstr, descrtr, netmaskstr, broadstr, dststr;
				if (description)
				{
					descrtr = char2CString(description);
				}
				else
				{
					descrtr = L"Network adapter with no description available";
				}
				m_log.InsertString(m_log.GetCount(), L"Discription: " + descrtr);
				mac = GetMACAddress(d);
				CString macstr;
				macstr.Format(L"MAC Address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
				m_log.InsertString(m_log.GetCount(), macstr);
				int i = 0;
				for (a = d->addresses; a != NULL; a = a->next)
				{
					if (a->addr->sa_family == AF_INET)  //�жϸõ�ַ�Ƿ�IP��ַ
					{
						/*CString family;
						family.Format(L"Address Family: #%d (AF_INET)", a->addr->sa_family);
						m_log.InsertString(m_log.GetCount(), family);  */
						if (a->addr)
						{
							addr = inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr);  //��ȡIP��ַ
							iplist.push_back(((struct sockaddr_in *)a->addr)->sin_addr.S_un.S_addr);
							addrstr = char2CString(addr);
							m_log.InsertString(m_log.GetCount(), L"IP Address: " + addrstr);
						}
						if (a->netmask)
						{
							netmask = inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr);	//��ȡ��������
							masklist.push_back(((struct sockaddr_in *)a->netmask)->sin_addr.S_un.S_addr);
							netmaskstr = char2CString(netmask);
							m_log.InsertString(m_log.GetCount(), L"Netmask: " + netmaskstr);
						}
						/*if (a->broadaddr)
						{
							broadaddr = inet_ntoa(((struct sockaddr_in *)a->broadaddr)->sin_addr);	//��ȡ�㲥��ַ
							broadstr = char2CString(broadaddr);
							m_log.InsertString(m_log.GetCount(), L"Broadcast Address: " + broadstr);
						}
						if (a->dstaddr)
						{
							dstaddr = inet_ntoa(((struct sockaddr_in *)a->dstaddr)->sin_addr);	//��ȡĿ�ĵ�ַ
							dststr = char2CString(dstaddr);
							m_log.InsertString(m_log.GetCount(), L"Destination Address: " + dststr);
						} */
						if (addrstr.GetLength() && netmaskstr.GetLength())
						{
							BYTE net[4], mask[4];
							regex iptest("(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)");
							string addr1(CString2char(addrstr)), netmask1(CString2char(netmaskstr));
							smatch result1, result2;
							regex_search(addr1, result1, iptest);
							regex_search(netmask1, result2, iptest);
							for (int i = 1; i < result1.size() && i < result2.size(); i++)
							{
								string tempstr1 = result1[i].str();
								string tempstr2 = result2[i].str();
								char *tempchar1 = (char *)(tempstr1.c_str());
								char *tempchar2 = (char *)(tempstr2.c_str());
								unsigned int t1 = atoi(tempchar1);
								unsigned int t2 = atoi(tempchar2);
								net[i - 1] = t1&t2;
								mask[i - 1] = t2;
							}
							//CString tab;
							//tab.Format(L"%s -- %d.%d.%d.%d -- is directly connected", char2CString(netmask), (int)net[0], (int)net[1], (int)net[2], (int)net[3]);
							RouterEntry *t = new RouterEntry;
							t->isDirect = true;
							t->ip = *(DWORD*)net;
							t->mask = *(DWORD*)mask;
							t->next = iplist[iplist.size() - 1];
							routerTable.push_back(t);
							//m_table.InsertString(m_table.GetCount(), tab);
						}
						m_start.EnableWindow(TRUE);
						m_add.EnableWindow(TRUE);
						m_dele.EnableWindow(TRUE);
					}
				}
				printrouterList();
				break;
			}
		}
	}

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CSimpleRouterDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CSimpleRouterDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CSimpleRouterDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

LRESULT CSimpleRouterDlg::OnPacket(WPARAM wParam, LPARAM lParam)
{
	pcap_pkthdr *pkt_header = (pcap_pkthdr *)wParam;
	const u_char *pkt_data = (const u_char *)lParam;

	u_int caplen = pkt_header->caplen;  //��ʾץ�������ݳ��ȣ�����İ���һ���������ģ�
	u_int len = pkt_header->len;	//��ʾ���ݰ���ʵ�ʳ���

	ICMP_t *ICMPPacket;
	ARPFrame_t *ARPPacket;
	//�����յ��İ�
	const u_char *newdata = (const u_char*)malloc(len);
	::memcpy((void*)newdata, pkt_data, len);
	ICMPPacket = (ICMP_t*)newdata;
	ARPPacket = (ARPFrame_t*)newdata;
	//�ж��Ƿ�ΪIP���ݱ�����̫������֡��������������
	if (len < sizeof(Data_t) || len < sizeof(ARPFrame_t))
		return 0;
	//��IP���ݱ���ipv4Э�飩
	if ((ntohs(ICMPPacket->FrameHeader.FrameType & (WORD)0xffff) == (WORD)0x0800)
		&& (ICMPPacket->IPHeader.Ver_HLen & (BYTE)0xf0) == (BYTE)0x40)
	{
		//�ж���̫��֡��Ŀ�ĵ�ַ�ǲ����Լ�
		if (strcmp(mactos(mac), mactos(ICMPPacket->FrameHeader.DesMAC)) != 0
			|| strcmp(mactos(mac), mactos(ICMPPacket->FrameHeader.SrcMAC)) == 0)
		{
			return 0;
		}

		pkt_no++;

		CString strlog;
		strlog.Format(L"Get an IP Datagram #%d: %s -> %s    %s -> %s", pkt_no, char2CString(iptos(ICMPPacket->IPHeader.SrcIP)),
			char2CString(iptos(ICMPPacket->IPHeader.DstIP)), char2CString(mactos(ICMPPacket->FrameHeader.SrcMAC)),
			char2CString(mactos(ICMPPacket->FrameHeader.DesMAC)));
		m_log.InsertString(m_log.GetCount(), strlog);

		WORD RecvChecksum, CalChecksum;
		RecvChecksum = ntohs(ICMPPacket->IPHeader.Checksum & (WORD)0xffff);
		CalChecksum = checkSum((const u_char*)&(ICMPPacket->IPHeader), 10, 20);

		//ȷ��ICMP������ݰ�����IP��Ӧ��ԴIP����ͬһ���磩
		int chooseip = -1;
		for (int i = 0; i < iplist.size(); i++)
		{
			if ((ICMPPacket->IPHeader.SrcIP&masklist[i]) == (iplist[i] & masklist[i]))
			{
				chooseip = i;
				break;
			}
		}
		if (chooseip == -1)
		{
			chooseip = iplist.size() - 1;
		}


		if (RecvChecksum != CalChecksum) //У��Ͳ���
		{
			strlog.Format(L"Drop packet #%d: Checksum error, 0x%.4x != 0x.4x", pkt_no, RecvChecksum,
				CalChecksum);
			m_log.InsertString(m_log.GetCount(), strlog);
			//����У��ʹ����ICMP���ݰ�
			sendICMPpkt(newdata, len, 0x12, 0x00, mac, iplist[chooseip]);
			return 0;
		}

		//׼����վ������һ��TTL
		ICMPPacket->IPHeader.TTL--;
		if (ICMPPacket->IPHeader.TTL <= 0)	//����֮��Ϊ0������������ICMP���ݰ���TTL��ʱ��
		{
			strlog.Format(L"Drop packet #%d: TTL exceeded in transit", pkt_no);
			m_log.InsertString(m_log.GetCount(), strlog);
			const u_char *old = (const u_char *)malloc(len);
			::memcpy((void*)old, pkt_data, len);
			sendICMPpkt(old, len, 0x0b, 0x00, mac, iplist[chooseip]); //������Ӧ����Դ����
			return 0;
		}

		//�ȿ����ǲ��Ǹ��Լ���
		int self = -1;
		for (int i = 0; i < iplist.size(); i++)
		{
			if (iplist[i] == ICMPPacket->IPHeader.DstIP)
			{
				self = i;
				break;
			}  
		}
		if (self >= 0) //�Ǹ��Լ���
		{
			if (ICMPPacket->IPHeader.Protocol == 0x01) //��ICMP���ݰ�
			{
				//���ظ�ICMP����ģ�������
				if (ICMPPacket->Type == 0x08)//�����ping������Ҫ�ظ�
				{
					strlog.Format(L"Reply the ping request #%d: %s -> %s    %s -> %s", pkt_no, char2CString(iptos(iplist[self])),
						char2CString(iptos(ICMPPacket->IPHeader.SrcIP)), char2CString(mactos(mac)),
						char2CString(mactos(ICMPPacket->FrameHeader.SrcMAC)));
					m_log.InsertString(m_log.GetCount(), strlog);
					sendICMPpkt(newdata, len, 0x08, 0x00, mac, iplist[self]);//�ظ�
				}
				else
				{
					strlog.Format(L"Drop packet #%d: Cannot repost the packet", pkt_no);
					m_log.InsertString(m_log.GetCount(), strlog);
				}
			}
			else
			{
				//�������ֱ�Ӷ���
				strlog.Format(L"Drop packet #%d: Cannot repost the packet", pkt_no);
				m_log.InsertString(m_log.GetCount(), strlog);
			}
			return 0;
		}

		//����������Ȳ�·�ɱ�
		int item = -1, maskcount = 0;
		for (int i = 0; i < routerTable.size(); i++)
		{
			if ((ICMPPacket->IPHeader.DstIP&routerTable[i]->mask) == routerTable[i]->ip)
			{
				DWORD m = routerTable[i]->mask;
				int j;
				for (j = 0; j < 32; j++) //����ǰ׺λ��
				{
					if (m % 2 != 1)
					{
						break;
					}
					m >>= 1;
				}
				if (j > maskcount) //�ƥ��
				{
					maskcount = j;
					item = i;
				}
			}
		}

		if (item < 0)//û�鵽���Ͷ�����������icmp �����粻�ɴ
		{
			strlog.Format(L"Drop packet #%d: Network %s is unreachable", 
				pkt_no, char2CString(iptos(ICMPPacket->IPHeader.DstIP&masklist[chooseip])));
			m_log.InsertString(m_log.GetCount(), strlog);
			sendICMPpkt(newdata, len, 0x03, 0x00, mac, iplist[chooseip]);
			return 0;
		}

		//��ip-macӳ�䣬�鲻�������棬��arp
		int find = -1;
		DWORD arpdstip;	 //Ҫ���͵�ARP�������Ŀ��IP
		if (routerTable[item]->isDirect) //��ֱ��Ͷ�ݵ�·�ɱ����ֱ�Ӱ���Ŀ��IP��ַͶ��
		{
			for (int i = 0; i < ipmacTable.size(); i++)	//�Ȳ�ip-macӳ��
			{
				if (ipmacTable[i]->ip == ICMPPacket->IPHeader.DstIP)
				{
					find = i;
					break;
				}
			}
			arpdstip = ICMPPacket->IPHeader.DstIP;
		}
		else
		{
			for (int i = 0; i < ipmacTable.size(); i++)
			{
				if (ipmacTable[i]->ip == routerTable[item]->next)
				{
					find = i;
					break;
				}
			}
			arpdstip = routerTable[item]->next;
		}
		if (find >= 0)
		{
			::memcpy((void*)(ICMPPacket->FrameHeader.DesMAC), ipmacTable[find]->mac, 6);
		}
		::memcpy((void*)(ICMPPacket->FrameHeader.SrcMAC), mac, 6);

		/*//׼����վ������һ��TTL
		ICMPPacket->IPHeader.TTL--;
		if (ICMPPacket->IPHeader.TTL <= 0)	//����֮��Ϊ0������������ICMP���ݰ���TTL��ʱ��
		{
			strlog.Format(L"Drop packet #%d: TTL exceeded", pkt_no);
			m_log.InsertString(m_log.GetCount(), strlog);
			const u_char *old = (const u_char *)malloc(len);
			::memcpy((void*)old, pkt_data, len);
			sendICMPpkt(old, len, 0x11, 0x00, mac, iplist[chooseip]); //������Ӧ����Դ����
			return 0;
		} */
		ICMPPacket->IPHeader.Checksum = htons(checkSum((const u_char*)&(ICMPPacket->IPHeader), 10, 20));

		//ȷ����һվARP���ݰ�����IP
		int chooseip2 = 0;
		for (int i = 0; i < iplist.size(); i++)
		{
			if ((arpdstip&masklist[i]) == (iplist[i] & masklist[i]))
			{
				chooseip2 = i;
				break;
			}
		}
		if (find < 0) //û�ҵ�ip-macӳ�䣬���棬��arp
		{
			DataBuf *t = new DataBuf;
			t->pkt_data = (const u_char*)malloc(len);
			t->old_pkt_data = (const u_char*)malloc(len);
			::memcpy((void*)(t->pkt_data), newdata, len);
			::memcpy((void*)(t->old_pkt_data), pkt_data, len);
			t->len = len;
			t->timeleft = 5;  //�ڻ����ڵ���ֵΪ5s���������ʱ���Զ�����
			t->timerid = timerid++;
			t->arpdstip = arpdstip;
			t->errmsgip = iplist[chooseip];
			t->pkt_no = pkt_no;
			SetTimer(t->timerid, 1000, NULL);

			BYTE broad[6];
			memset(broad, 0xff, 6);

			t->arpsrcip = iplist[chooseip2];
			strlog.Format(L"Push IP Datagram #%d into buffer: %s -> %s    %s -> %s", pkt_no, char2CString(iptos(t->arpsrcip)),
				char2CString(iptos(t->arpdstip)), char2CString(mactos(mac)), L"(unknown MAC address)");
			m_log.InsertString(m_log.GetCount(), strlog);
			if (buffer.size() < MAXQUEUE)
			{
				buffer.push_back(t);
			}
			else  //��������
			{
				strlog.Format(L"Drop packet #%d: The buffer is full", pkt_no);
				m_log.InsertString(m_log.GetCount(), strlog);
				const u_char *old = (const u_char *)malloc(len);
				::memcpy((void*)old, pkt_data, len);
				sendICMPpkt(old, len, 0x04, 0x00, mac, iplist[chooseip]);
				return 0;
			}
			strlog.Format(L"Send an ARP request: MAC address of %s", char2CString(iptos(t->arpdstip)));
			m_log.InsertString(m_log.GetCount(), strlog);
			sendARPpkt(mac, broad, iplist[chooseip2], arpdstip, 0x0001);
			return 0;
		}

		//ת�����ݰ�
		if (pcap_sendpacket(adhandle, (const u_char*)ICMPPacket, len) != 0)
		{
			//���ʹ�����
			CString error;
			error.Format(L"Error sending the packet: %s", pcap_geterr(adhandle));
			AfxMessageBox(error);
			return 0;
		}
		strlog.Format(L"Repost IP Datagram #%d: %s -> %s    %s -> %s", pkt_no, char2CString(iptos(iplist[chooseip2])),
			char2CString(iptos(arpdstip)), char2CString(mactos(mac)), char2CString(mactos(ICMPPacket->FrameHeader.DesMAC)));
		m_log.InsertString(m_log.GetCount(), strlog);
		return 0;
	}
	//��ARP֡��ipv4Э�飩
	else if ((ntohs(ARPPacket->FrameHeader.FrameType & (WORD)0xffff) == (WORD)0x0806)
		&& (ntohs(ARPPacket->HardwareType & (WORD)0xffff) == (WORD)0x0001)
		&& (ntohs(ARPPacket->ProtocolType & (WORD)0xffff) == (WORD)0x0800)
		&& (ARPPacket->HLen == 6)
		&& (ARPPacket->PLen == 4)
		)
	{
		bool broadcast = false;
		if (strcmp(mactos(mac), mactos(ICMPPacket->FrameHeader.DesMAC)) != 0
			&& (broadcast=macBroadcast(ICMPPacket->FrameHeader.DesMAC))==false
			|| strcmp(mactos(mac), mactos(ICMPPacket->FrameHeader.SrcMAC)) == 0)
		{
			/*CString strlog;
			if (strcmp(mactos(mac), mactos(ICMPPacket->FrameHeader.DesMAC)) != 0)
			{
				strlog.Format(L"aaa dst:%s", char2CString(mactos(ICMPPacket->FrameHeader.DesMAC)));
				m_log.InsertString(m_log.GetCount(), strlog);
			}
			else if (broadcast == false)
			{
				strlog.Format(L"bbb dst:%s", char2CString(mactos(ICMPPacket->FrameHeader.DesMAC)));
				m_log.InsertString(m_log.GetCount(), strlog);
			}
			else if (strcmp(mactos(mac), mactos(ICMPPacket->FrameHeader.SrcMAC)) == 0)
			{
				strlog.Format(L"bbb src:%s", char2CString(mactos(ICMPPacket->FrameHeader.SrcMAC)));
				m_log.InsertString(m_log.GetCount(), strlog);
			}	   */
			return 0;
		}
		pkt_no++;
		CString strlog;
		if (ARPPacket->Operation == ntohs(0x0001)) //����
		{
			//����Ƕ��Լ������󣬾ͷ���Ӧ��
			if (ARPPacket->RecvIP == iplist[0])
			{
				strlog.Format(L"Get an ARP request #%d: %s request for MAC of %s", pkt_no, char2CString(iptos(ARPPacket->SendIP)),
					char2CString(iptos(ARPPacket->RecvIP)));
				m_log.InsertString(m_log.GetCount(), strlog);
				strlog.Format(L"Reply ARP request #%d: %s is at %s", pkt_no, char2CString(iptos(ARPPacket->RecvIP)),
					char2CString(mactos(mac)));
				m_log.InsertString(m_log.GetCount(), strlog);
				sendARPpkt(mac, ARPPacket->SendHa, iplist[0], ARPPacket->SendIP, 0x0002);
			}
			else if (ARPPacket->RecvIP == iplist[1])
			{
				strlog.Format(L"Get an ARP request #%d: %s request for MAC of %s", pkt_no, char2CString(iptos(ARPPacket->SendIP)),
					char2CString(iptos(ARPPacket->RecvIP)));
				m_log.InsertString(m_log.GetCount(), strlog);
				strlog.Format(L"Reply ARP request #%d: %s is at %s", pkt_no, char2CString(iptos(ARPPacket->RecvIP)),
					char2CString(mactos(mac)));
				m_log.InsertString(m_log.GetCount(), strlog);
				sendARPpkt(mac, ARPPacket->SendHa, iplist[1], ARPPacket->SendIP, 0x0002);
			}
		}
		else if (ARPPacket->Operation == ntohs(0x0002))	//��Ӧ
		{
			//����Ƕ��Լ�����Ӧ���ͻ���ARP����������ڻ����е����ݰ�
			strlog.Format(L"Get an ARP reply #%d: %s is at %s", pkt_no, char2CString(iptos(ARPPacket->SendIP)),
				char2CString(mactos(ARPPacket->SendHa)));
			m_log.InsertString(m_log.GetCount(), strlog);

			IPMACEntry *t = new IPMACEntry;
			t->ip = ARPPacket->SendIP;
			::memcpy((void*)(t->mac), ARPPacket->SendHa, 6);
			int hasmap = -1;
			for (int i = 0; i < ipmacTable.size(); i++)
			{
				if (t->ip == ipmacTable[i]->ip)
				{
					hasmap = i;
					break;
				}
			}
			if (hasmap >= 0) //���ӳ������Ѵ��ڸ�ARP����͸��´˱���
			{
				ipmacTable.erase(ipmacTable.begin() + hasmap);
			}
			ipmacTable.push_back(t);

			//����������û����ת�������ݰ�
			if (buffer.size() == 0)
				return 0;
			vector<DataBuf*>::iterator it;
			for (it = buffer.begin(); it != buffer.end(); )
			{
				ICMP_t *olddata = (ICMP_t*)((*it)->pkt_data);
				int find = -1;
				for (int j = 0; j < ipmacTable.size(); j++)
				{
					if (ipmacTable[j]->ip == (*it)->arpdstip)
					{
						find = j;
						break;
					}
				}
				if (find < 0)  //��Ȼ�Ҳ���ӳ�䣬���������ARP����
				{
					BYTE broad[6];
					memset(broad, 0xff, 6);

					sendARPpkt(mac, broad, (*it)->arpsrcip, (*it)->arpdstip, 0x0001);
					it++;
					continue;
				}
				//�ҵ�ӳ����
				::memcpy((void*)(olddata->FrameHeader.DesMAC), ipmacTable[find]->mac, 6);
				olddata->IPHeader.Checksum = htons(checkSum((const u_char*)&(olddata->IPHeader), 10, 20));
				KillTimer((*it)->timerid);
				//ת�����ݰ�
				if (pcap_sendpacket(adhandle, (const u_char*)olddata, (*it)->len) != 0)
				{
					//���ʹ�����
					CString error;
					error.Format(L"Error sending the packet: %s", pcap_geterr(adhandle));
					AfxMessageBox(error);
					return 0;
				}
				strlog.Format(L"Repost IP Datagram #%d from buffer: %s -> %s    %s -> %s", pkt_no, char2CString(iptos((*it)->arpsrcip)),
					char2CString(iptos((*it)->arpdstip)), char2CString(mactos(mac)), char2CString(mactos(olddata->FrameHeader.DesMAC)));
				m_log.InsertString(m_log.GetCount(), strlog);
				it = buffer.erase(it);
			}
		}
		return 0;
	}

	//���������������İ��򵥶���

	return 0;
}

void CSimpleRouterDlg::printrouterList()
{
	m_table.ResetContent();
	for (int i = 0; i < routerTable.size(); i++)
	{
		CString temp;
		BYTE *mask, *net, *next;
		RouterEntry *item = routerTable[i];
		mask = (BYTE*)&(item->mask);
		net = (BYTE*)&(item->ip);
		next = (BYTE*)&(item->next);
		if (item->isDirect)
		{
			temp.Format(L"%d.%d.%d.%d -- %d.%d.%d.%d -- is directly connected",(int)mask[0],(int)mask[1],(int)mask[2],(int)mask[3],
				(int)net[0], (int)net[1], (int)net[2], (int)net[3]);
		}
		else
		{
			temp.Format(L"%d.%d.%d.%d -- %d.%d.%d.%d -- %d.%d.%d.%d", (int)mask[0], (int)mask[1], (int)mask[2], (int)mask[3],
				(int)net[0], (int)net[1], (int)net[2], (int)net[3],
				(int)next[0], (int)next[1], (int)next[2], (int)next[3]);
		}
		m_table.InsertString(m_table.GetCount(), temp);
	}
}

u_char *CSimpleRouterDlg::GetMACAddress(pcap_if_t *d)
{
	LPADAPTER lpAdapter = 0;
	int i = 0;
	DWORD dwErrorCode;
	PPACKET_OID_DATA OidData;
	BOOLEAN Status;
	u_char *MACaddr = new u_char[6];	//�洢MAC��ַ
	memset(MACaddr, 0, 6 * sizeof(u_char));

	string macstr(d->name);
	macstr = macstr.substr(8); //������Ҫ������������û��ǰ׺rpcap://�ģ���ȥ��
	lpAdapter = PacketOpenAdapter((char *)(macstr.c_str()));  //ͨ���������ƴ�ָ��������
	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		dwErrorCode = GetLastError();
		CString error;
		error.Format(L"Unable to open the adapter, Error Code : %lx", dwErrorCode);
		AfxMessageBox(error);
	}
	else
	{
		OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA)); // ΪMAC��ַ����ռ�
																		 //OldData�е�Data�������ֻ��һ���ֽڵģ���MAC��ַ6���ֽڣ�����Ҫ��MAC��ַ����ռ�
		if (OidData == NULL)
		{
			dwErrorCode = GetLastError();
			CString error;
			error.Format(L"Error allocating memory!");
			PacketCloseAdapter(lpAdapter);
		}
		else
		{
			OidData->Oid = OID_802_3_CURRENT_ADDRESS;  // OID��code��ָ��Ҫ��ȡ������֡����Ϊ��̫��֡��802.3����ʽ�ĵ�ǰʹ�õĵ�ַ��MAC��ַ��
			OidData->Length = 6;  //��ԱData�ĳ��ȣ�MAC��ַ�ĳ���
			ZeroMemory(OidData->Data, 6); //�Ƚ�Data���ʼ��Ϊ0����ͬ����memset��ʼ��
			Status = PacketRequest(lpAdapter, FALSE, OidData); //����������OID����MAC��ַ������OidData->Data��
			if (Status)	//�������ط�0ֵ���óɹ�
			{
				for (int i = 0; i < 6; i++)
					MACaddr[i] = (OidData->Data)[i];
			}
			free(OidData); //�ͷ�OldData�Ŀռ�
			PacketCloseAdapter(lpAdapter); //�ر������豸
		}
	}
	return MACaddr;
}

void CSimpleRouterDlg::OnCbnSelchangeInterf()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if (sel == m_interf.GetCurSel())
	{
		return;
	}
	iplist.clear();
	masklist.clear();
	routerTable.clear();
	ipmacTable.clear();
	buffer.clear();
	timerid = 1;
	pkt_no = 0;
	m_start.EnableWindow(FALSE);
	m_stop.EnableWindow(FALSE);
	m_add.EnableWindow(FALSE);
	m_dele.EnableWindow(FALSE);
	sel = m_interf.GetCurSel();
	m_log.ResetContent();
	m_table.ResetContent();
	CString strText;
	int nCurSel;
	nCurSel = m_interf.GetCurSel();
	m_interf.GetLBText(nCurSel, strText);
	pcap_if_t *d;
	pcap_addr_t *a;
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
	char errbuf2[PCAP_ERRBUF_SIZE];

	for (d = alldevs; d != NULL; d = d->next)
	{
		char *name = d->name;  //����d->name��ȡ������ӿ��豸������
		CString namestr = char2CString(name);  //ʹ�ú���char2CString()��Ϊ�˽����������
		if (namestr == strText)
		{
			char *description = d->description;	 //����d->description��ȡ������ӿ��豸��������Ϣ
			char *addr, *netmask, *broadaddr, *dstaddr;
			CString addrstr, descrtr, netmaskstr, broadstr, dststr;
			if (description)
			{
				descrtr = char2CString(description);
			}
			else
			{
				descrtr = L"Network adapter with no description available";
			}
			m_log.InsertString(m_log.GetCount(), L"Discription: " + descrtr);
			mac = GetMACAddress(d);
			CString macstr;
			macstr.Format(L"MAC Address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			m_log.InsertString(m_log.GetCount(), macstr);
			int i = 0;
			for (a = d->addresses; a != NULL; a = a->next)
			{
				if (a->addr->sa_family == AF_INET)  //�жϸõ�ַ�Ƿ�IP��ַ
				{
					/*CString family;
					family.Format(L"Address Family: #%d (AF_INET)", a->addr->sa_family);
					m_log.InsertString(m_log.GetCount(), family);  */
					if (a->addr)
					{
						addr = inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr);  //��ȡIP��ַ
						iplist.push_back(((struct sockaddr_in *)a->addr)->sin_addr.S_un.S_addr);
						addrstr = char2CString(addr);
						m_log.InsertString(m_log.GetCount(), L"IP Address: " + addrstr);
					}
					if (a->netmask)
					{
						netmask = inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr);	//��ȡ��������
						masklist.push_back(((struct sockaddr_in *)a->netmask)->sin_addr.S_un.S_addr);
						netmaskstr = char2CString(netmask);
						m_log.InsertString(m_log.GetCount(), L"Netmask: " + netmaskstr);
					}
					/*if (a->broadaddr)
					{
					broadaddr = inet_ntoa(((struct sockaddr_in *)a->broadaddr)->sin_addr);	//��ȡ�㲥��ַ
					broadstr = char2CString(broadaddr);
					m_log.InsertString(m_log.GetCount(), L"Broadcast Address: " + broadstr);
					}
					if (a->dstaddr)
					{
					dstaddr = inet_ntoa(((struct sockaddr_in *)a->dstaddr)->sin_addr);	//��ȡĿ�ĵ�ַ
					dststr = char2CString(dstaddr);
					m_log.InsertString(m_log.GetCount(), L"Destination Address: " + dststr);
					} */
					if (addrstr.GetLength() && netmaskstr.GetLength())
					{
						BYTE net[4], mask[4];
						regex iptest("(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)");
						string addr1(CString2char(addrstr)), netmask1(CString2char(netmaskstr));
						smatch result1, result2;
						regex_search(addr1, result1, iptest);
						regex_search(netmask1, result2, iptest);
						for (int i = 1; i < result1.size() && i < result2.size(); i++)
						{
							string tempstr1 = result1[i].str();
							string tempstr2 = result2[i].str();
							char *tempchar1 = (char *)(tempstr1.c_str());
							char *tempchar2 = (char *)(tempstr2.c_str());
							unsigned int t1 = atoi(tempchar1);
							unsigned int t2 = atoi(tempchar2);
							net[i - 1] = t1&t2;
							mask[i - 1] = t2;
						}
						//CString tab;
						//tab.Format(L"%s -- %d.%d.%d.%d -- is directly connected", char2CString(netmask), (int)net[0], (int)net[1], (int)net[2], (int)net[3]);
						RouterEntry *t = new RouterEntry;
						t->isDirect = true;
						t->ip = *(DWORD*)net;
						t->mask = *(DWORD*)mask;
						t->next = iplist[iplist.size() - 1];
						routerTable.push_back(t);
						//m_table.InsertString(m_table.GetCount(), tab);
					}
					m_start.EnableWindow(TRUE);
					m_add.EnableWindow(TRUE);
					m_dele.EnableWindow(TRUE);
				}
			}
			printrouterList();
			break;
		}
	}
}


void CSimpleRouterDlg::OnBnClickedAdd()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if (m_mask.IsBlank() || m_dest.IsBlank() || m_next.IsBlank())
	{
		AfxMessageBox(L"�������벻��Ϊ�գ�");
		return;
	}
	if (m_dest.IsBlank())
	{
		AfxMessageBox(L"Ŀ�ĵ�ַ����Ϊ�գ�");
		return;
	}
	if (m_next.IsBlank())
	{
		AfxMessageBox(L"��һ��������Ϊ�գ�");
		return;
	}
	BYTE mask[4], dest[4], next[4];
	m_mask.GetAddress(mask[0], mask[1], mask[2], mask[3]);
	m_dest.GetAddress(dest[0], dest[1], dest[2], dest[3]);
	m_next.GetAddress(next[0], next[1], next[2], next[3]);
	int i;
	DWORD m = *(DWORD*)mask;
	for (i = 1; i <= 32; i++) //�ȼ����������ĺϷ���
	{
		if (m % 2 != 1)
		{
			break;
		}
		m >>= 1;
	}
	if (m != 0)
	{
		AfxMessageBox(L"�������벻�Ϸ���");
		return;
	}
	for (i = 0; i < 4; i++)
	{
		if ((mask[i] | dest[i]) != mask[i])
		{
			AfxMessageBox(L"Ŀ�ĵ�ַ���������벻һ�£�");
			return;
		}
	}

	//�ж���һ�����Ƿ����Լ��Ľӿ�IP
	for (int i = 0; i < iplist.size(); i++)
	{
		if (iplist[i] == (*(DWORD*)next))
		{
			AfxMessageBox(L"���ܽ���һ������Ϊ��·����IP��");
			return;
		}
	}

	bool reachable = false;
	for (i = 0; i < routerTable.size(); i++)	
	{
		if (!routerTable[i]->isDirect)
		{
			if (routerTable[i]->ip == (*(DWORD*)dest) && routerTable[i]->mask == (*(DWORD*)mask)
				&& routerTable[i]->next == (*(DWORD*)next))
			{
				AfxMessageBox(L"�Ѵ��ڴ�·�ɱ���޷���ӣ�");
				return;
			}
		}
		else
		{
			if (routerTable[i]->ip == (*(DWORD*)dest) && routerTable[i]->mask == (*(DWORD*)mask))
			{
				AfxMessageBox(L"�����������Ŀ�ĵ�ַ���Ѵ���ֱ��������·�ɱ���޷���ӣ�");
				return;
			}
		}
		/*if (((*(DWORD*)mask) & (*(DWORD*)next)) == routerTable[i]->ip)
		{
			reachable = true;
		}  */
	}
	/*if (!reachable)	//�ж���һ�����Ƿ�����·����ֱ������������
	{
		AfxMessageBox(L"��һ���������粻����·����ֱ�����������磡�޷���ӣ�");
		return;
	}  */

	RouterEntry *t = new RouterEntry;
	t->ip = (*(DWORD*)dest);
	t->mask = (*(DWORD*)mask);
	t->next = (*(DWORD*)next);
	t->isDirect = false;
	routerTable.push_back(t);
	printrouterList();
	MessageBox(L"����ɹ���", L"SimpleRouter", MB_OK | MB_ICONINFORMATION);
}


void CSimpleRouterDlg::OnBnClickedDele()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if (m_table.GetCount() == 0)
	{
		AfxMessageBox(L"��ǰ������·�ɱ�Ϊ�գ�");
		return;
	}
	int nCurSel = m_table.GetCurSel();
	if (nCurSel == -1)
	{
		AfxMessageBox(L"��ѡ��һ��·�ɱ��");
		return;
	}
	CString choose;
	m_table.GetText(nCurSel, choose);
	if (choose.Find(L"is directly connected") >= 0)
	{
		AfxMessageBox(L"����ɾ��ֱ��������·�ɱ��");
		return;
	}
	routerTable.erase(routerTable.begin() + nCurSel);
	printrouterList();
	MessageBox(L"ɾ���ɹ���", L"SimpleRouter", MB_OK | MB_ICONINFORMATION);
}


void CSimpleRouterDlg::OnBnClickedStart()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if (!m_interf.GetCount())
	{
		AfxMessageBox(L"����û�п��õ���̫���ӿڣ�");
		return;
	}

	isStopped = false;
	CString strText;
	int nCurSel;
	nCurSel = m_interf.GetCurSel();
	m_interf.GetLBText(nCurSel, strText);
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
	char *devname = CString2char(strText);
	pcap_if_t *d;

	for (d = alldevs; d != NULL; d = d->next)
	{
		char *name = d->name;
		CString namestr = char2CString(name);
		if (namestr == strText)
			break;
	}

	m_interf.EnableWindow(FALSE);
	m_start.EnableWindow(FALSE);
	m_stop.EnableWindow(TRUE);

	//�������豸�����û��ģʽ
	//65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
	//��ʱΪ1s
	if ((adhandle = pcap_open_live(devname, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) == NULL)
	{
		CString error;
		error.Format(L"Unable to open the adapter. \n%s is not supported by WinPcap", strText);
		AfxMessageBox(error);
		// fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		return;
	}

	m_capturer = AfxBeginThread(capturer, NULL, THREAD_PRIORITY_NORMAL);
}


void CSimpleRouterDlg::OnBnClickedStop()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	isStopped = true;
	m_interf.EnableWindow(TRUE);
	m_start.EnableWindow(TRUE);
	m_stop.EnableWindow(FALSE);
}


void CSimpleRouterDlg::OnClose()
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ
	if (MessageBox(L"ȷ���˳���", L"SimpleRouter", MB_YESNO | MB_ICONQUESTION) == IDYES)
	{
		if (!isStopped)
		{
			isStopped = true;
		}
		//�ͷ��豸�б�
		pcap_freealldevs(alldevs);
		CDialogEx::OnClose();
	}
}


void CSimpleRouterDlg::OnOK()
{
	// TODO: �ڴ����ר�ô����/����û���

	//CDialogEx::OnOK();
}


void CSimpleRouterDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ
	if (buffer.size() == 0)
	{
		return;
	}
	CString strlog;
	vector<DataBuf*>::iterator it;
	for (it = buffer.begin(); it != buffer.end(); )
	{
		if ((*it)->timerid == nIDEvent)
		{
			KillTimer((*it)->timerid);
			(*it)->timeleft--;
			if ((*it)->timeleft == 0)
			{
				//Ŀ���������ɴ�
				strlog.Format(L"Drop packet #%d: Host %s is unreachable",
					pkt_no, char2CString(iptos(((ICMP_t*)((*it)->old_pkt_data))->IPHeader.DstIP)));
				m_log.InsertString(m_log.GetCount(), strlog);
				sendICMPpkt((*it)->old_pkt_data, (*it)->len, 0x03, 0x01, mac, (*it)->errmsgip);
				it = buffer.erase(it);
				continue;
			}
			ICMP_t *olddata = (ICMP_t*)((*it)->pkt_data);
			int find = -1;
			for (int j = 0; j < ipmacTable.size(); j++)
			{
				if (ipmacTable[j]->ip == (*it)->arpdstip)
				{
					find = j;
					break;
				}
			}
			if (find < 0)  //��Ȼ�Ҳ���ӳ�䣬���������ARP����
			{
				BYTE broad[6];
				memset(broad, 0xff, 6);

				sendARPpkt(mac, broad, (*it)->arpsrcip, (*it)->arpdstip, 0x0001);
				SetTimer((*it)->timerid, 1000, NULL);
				continue;
			}
			//�ҵ�ӳ����
			::memcpy((void*)(olddata->FrameHeader.DesMAC), ipmacTable[find]->mac, 6);
			olddata->IPHeader.Checksum = htons(checkSum((const u_char*)&(olddata->IPHeader), 10, 20));

			//ת�����ݰ�
			if (pcap_sendpacket(adhandle, (const u_char*)olddata, (*it)->len) != 0)
			{
				//���ʹ�����
				CString error;
				error.Format(L"Error sending the packet: %s", pcap_geterr(adhandle));
				AfxMessageBox(error);
				return;
			}
			strlog.Format(L"Repost IP Datagram #%d from buffer: %s -> %s    %s -> %s", pkt_no, char2CString(iptos((*it)->arpsrcip)),
				char2CString(iptos((*it)->arpdstip)), char2CString(mactos(mac)), char2CString(mactos(olddata->FrameHeader.DesMAC)));
			m_log.InsertString(m_log.GetCount(), strlog);
			//popqueue.push_back(i);
		}
		it++;
	}
	//popqueue.clear();
	CDialogEx::OnTimer(nIDEvent);
}


void CSimpleRouterDlg::OnBnClickedClear()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_log.ResetContent();
}
