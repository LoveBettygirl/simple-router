
// SimpleRouter.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CSimpleRouterApp: 
// �йش����ʵ�֣������ SimpleRouter.cpp
//

class CSimpleRouterApp : public CWinApp
{
public:
	CSimpleRouterApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CSimpleRouterApp theApp;