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

// RansWSimulatorDlg.cpp : implementation file
//

#include "stdafx.h"
#include "RansWSimulator.h"
#include "RansWSimulatorDlg.h"
#include "afxdialogex.h"
#include "RansEngine.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
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


// CRansWSimulatorDlg dialog



CRansWSimulatorDlg::CRansWSimulatorDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_RANSWSIMULATOR_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CRansWSimulatorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CRansWSimulatorDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_APPLY, &CRansWSimulatorDlg::OnBnClickedRunRansW)
	ON_WM_TIMER()
END_MESSAGE_MAP()


// CRansWSimulatorDlg message handlers

const char* pDescription = R"DESC(
Descriptions:
EduRansW is designed for educational purposes, to teach about ransomware decryption and exploitation methods. It introduces specific vulnerabilities for practical learning experiences in cybersecurity training programs.

Summary:
- Upon clicking "Run Ransomware," a simulated ransomware starts its operation.
- Initially, the malware searches for a directory to attack. For demonstration purposes, a directory named "CryptPath" is created in the current directory and designated as the target directory.
- Subsequently, a session key (encryption key), unique to every user (generated uniquely for every computer), is created and stored in a specific location (e.g., registry).
  All files in the target directory are encrypted using this key.
- Following the encryption, a countdown timer starts, with a deadline set to 24 hours.
- Attempting to open the encrypted files triggers a window that prompts the user to pay a ransom to a randomly generated but valid BTC address.
- There is a real payment checking mechanism. Clicking "Verify Payment" after sending real money should result in decryption like a real ransomware.
- The objective is to identify vulnerabilities in the malware's operational methods and decrypt your test data in the target directory (CryptPath).


Disclaimer:
By using this application, users acknowledge its educational purpose and agree that it should only be used for educational purposes. Furthermore, users agree that WebSec B.V. shall not be held liable for any damages that may arise from its use.

This application is developed by WebSec® B.V.
2024 © All rights reserved [https://websec.nl]
)DESC";

BOOL CRansWSimulatorDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
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

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	SetDlgItemTextA(this->GetSafeHwnd(), IDC_STATIC_DESC, pDescription);

	if (!initRansomwareAttack())
	{
		::MessageBoxA(this->GetSafeHwnd(), "Initializing failure! Run as Administrator.", "EduRansW", MB_ICONERROR);
	}

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CRansWSimulatorDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CRansWSimulatorDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CRansWSimulatorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CRansWSimulatorDlg::OnBnClickedRunRansW()
{
	// TODO: Add your control notification handler code here

	if (runRansomware())
	{
		::MessageBoxA(this->GetSafeHwnd(), "Successfully attacked!", "EduRansW", MB_OK);
	}
	else
	{
		::MessageBoxA(this->GetSafeHwnd(), "Error has occurred on attacking. Try again", "EduRansW", MB_ICONERROR);
	}
}


