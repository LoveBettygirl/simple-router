#pragma once


// CMyListBox

class CMyListBox : public CListBox
{
	DECLARE_DYNAMIC(CMyListBox)

public:
	CMyListBox();
	virtual ~CMyListBox();
	int AddString(LPCTSTR lpszItem);
	int InsertString(int nIndex, LPCTSTR lpszItem);

	// ����ˮƽ���������
	void RefushHorizontalScrollBar(void);
	void ResetContent();

protected:
	DECLARE_MESSAGE_MAP()
};


