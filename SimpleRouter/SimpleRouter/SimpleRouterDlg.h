
// SimpleRouterDlg.h : 头文件
//

#pragma once
#include "pcap.h"
#include "MyListBox.h"
#include "afxwin.h"
#include "afxcmn.h"
#include "Packet32.h"
#include <vector>
#include <string>
#include <regex>
#include <unordered_map>
#include <queue>
using namespace std;
#define WM_PACKET WM_USER+1
#define MAXQUEUE 10000


// CSimpleRouterDlg 对话框
class CSimpleRouterDlg : public CDialogEx
{
// 构造
public:
	CSimpleRouterDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SIMPLEROUTER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg LRESULT OnPacket(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()
public:
	CComboBox m_interf;
	CMyListBox m_log;
	CMyListBox m_table;
	CIPAddressCtrl m_mask;
	CIPAddressCtrl m_dest;
	CIPAddressCtrl m_next;
	CButton m_start;
	CButton m_stop;
	CButton m_add;
	CButton m_dele;
	pcap_if_t *alldevs;  //指向设备链表首部的指针
	pcap_t *adhandle;
	bool isStopped;
	//static int pkt_count;
	int devices;
	int sel;
	u_char *GetMACAddress(pcap_if_t *d);
	afx_msg void OnCbnSelchangeInterf();
	afx_msg void OnBnClickedAdd();
	afx_msg void OnBnClickedDele();
	afx_msg void OnBnClickedStart();
	CWinThread *m_capturer;
	afx_msg void OnBnClickedStop();
	afx_msg void OnClose();
	virtual void OnOK();
	vector<DWORD> iplist;//本网卡的IP
	vector<DWORD> masklist;//本网卡的掩码（顺序一一对应）
	u_char *mac;
	void printrouterList();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	CButton m_clear;
	afx_msg void OnBnClickedClear();
};
