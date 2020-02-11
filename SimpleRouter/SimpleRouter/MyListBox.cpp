// MyListBox.cpp : 实现文件
//

#include "stdafx.h"
#include "SimpleRouter.h"
#include "MyListBox.h"


// CMyListBox

IMPLEMENT_DYNAMIC(CMyListBox, CListBox)

CMyListBox::CMyListBox()
{

}

CMyListBox::~CMyListBox()
{
}


BEGIN_MESSAGE_MAP(CMyListBox, CListBox)
END_MESSAGE_MAP()



// CMyListBox 消息处理程序

int CMyListBox::AddString(LPCTSTR lpszItem)
{
	int nResult = CListBox::AddString(lpszItem);
	RefushHorizontalScrollBar();
	return nResult;
}
int CMyListBox::InsertString(int nIndex, LPCTSTR lpszItem)
{
	int nResult = CListBox::InsertString(nIndex, lpszItem);
	RefushHorizontalScrollBar();
	return nResult;
}
void CMyListBox::RefushHorizontalScrollBar(void)
{
	int a = CListBox::GetHorizontalExtent();
	CDC *pDC = this->GetDC();
	if (NULL == pDC)
	{
		return;
	}
	int nCount = this->GetCount();
	if (nCount < 1)
	{
		this->SetHorizontalExtent(0);
		return;
	}
	int nMaxExtent = 0;
	CString szText;
	for (int i = 0; i < nCount; ++i)
	{
		this->GetText(i, szText);
		CSize &cs = pDC->GetTextExtent(szText);
		if (cs.cx > nMaxExtent)
		{
			nMaxExtent = cs.cx;
		}
	}
	int temp = nMaxExtent*0.5;
	this->SetHorizontalExtent(nMaxExtent + temp);
}

void CMyListBox::ResetContent()
{
	CListBox::ResetContent();
	CListBox::SetHorizontalExtent(0);
}
