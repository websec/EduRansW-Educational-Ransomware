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

// RansWSimulator.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "RansWSimulator.h"
#include "RansWSimulatorDlg.h"
#include "RansEngine.h"
#include "RansomDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CRansWSimulatorApp

BEGIN_MESSAGE_MAP(CRansWSimulatorApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CRansWSimulatorApp construction

CRansWSimulatorApp::CRansWSimulatorApp()
{
	// support Restart Manager
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;

	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CRansWSimulatorApp object

CRansWSimulatorApp theApp;


// CRansWSimulatorApp initialization

bool registerShell()
{
	HKEY hRoot;
	HKEY hChild;
	HKEY hKey;
	LONG ret;

	CHAR path[512] = { NULL };
	CHAR iconPath[512] = { NULL };
	CHAR exePath[512] = { NULL };

	DWORD cbData = 512;
	DWORD error;

	GetModuleFileNameA(NULL, path, 512);

	if (RegCreateKeyA(HKEY_CLASSES_ROOT, "RansWSimulator", &hRoot) == ERROR_SUCCESS)
	{
		if (RegCreateKeyA(hRoot, "DefaultIcon", &hChild) == ERROR_SUCCESS)
		{
			lstrcpyA(iconPath, path);
			lstrcatA(iconPath, ",0");

			cbData = lstrlenA(iconPath);

			if (RegSetKeyValueA(hChild, NULL, NULL, REG_SZ, (LPBYTE)iconPath, cbData) != ERROR_SUCCESS)
			{
				error = GetLastError();
				return false;
			}
		}

		if (RegCreateKeyA(hRoot, "shell", &hChild) == ERROR_SUCCESS)
		{
			if (RegCreateKeyA(hChild, "open", &hKey) == ERROR_SUCCESS)
			{
				if (RegCreateKeyA(hKey, "command", &hKey) == ERROR_SUCCESS)
				{
					lstrcpyA(exePath, "\"");
					lstrcatA(exePath, path);
					lstrcatA(exePath, "\"");
					lstrcatA(exePath, " \"%1\"");

					cbData = lstrlenA(exePath);

					if (RegSetKeyValueA(hKey, NULL, NULL, REG_SZ, (LPBYTE)exePath, cbData) != ERROR_SUCCESS)
					{
						error = GetLastError();
						return false;
					}
				}
			}
			RegCloseKey(hChild);
		}
	}

	RegCloseKey(hRoot);

	if (RegCreateKeyA(HKEY_CLASSES_ROOT, ".eduransw", &hRoot) == ERROR_SUCCESS)
	{
		if (RegSetKeyValueA(hRoot, NULL, NULL, REG_SZ, (LPBYTE)"RansWSimulator", lstrlenA("RansWSimulator")) != ERROR_SUCCESS)
		{
			return false;
		}
	}

	return true;
}

BOOL CRansWSimulatorApp::InitInstance()
{
	// InitCommonControlsEx() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// Set this to include all the common control classes you want to use
	// in your application.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();


	AfxEnableControlContainer();

	// Create the shell manager, in case the dialog contains
	// any shell tree view or shell list view controls.
	CShellManager *pShellManager = new CShellManager;

	// Activate "Windows Native" visual manager for enabling themes in MFC controls
	CMFCVisualManager::SetDefaultManager(RUNTIME_CLASS(CMFCVisualManagerWindows));

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	// of your final executable, you should remove from the following
	// the specific initialization routines you do not need
	// Change the registry key under which our settings are stored
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization
	SetRegistryKey(_T("Local AppWizard-Generated Applications"));

	const char szUniqueNamedMutex[] = "RansWSimulator";
	HANDLE hHandle = CreateMutexA(NULL, TRUE, szUniqueNamedMutex);
	if (ERROR_ALREADY_EXISTS == GetLastError())
	{
		CloseHandle(hHandle);
		return FALSE;
	}

	registerShell();

	WCHAR* commandLine;
	LPWSTR* args;
	int argNum;

	commandLine = GetCommandLineW();

	args = CommandLineToArgvW(commandLine, &argNum);
	
	if (argNum > 1)
	{
		RansomDlg ransomDlg(args[1]);
		ransomDlg.DoModal();
	}
	else
	{
		CRansWSimulatorDlg dlg;
		m_pMainWnd = &dlg;
		INT_PTR nResponse = dlg.DoModal();
		if (nResponse == IDOK)
		{
			// TODO: Place code here to handle when the dialog is
			//  dismissed with OK
		}
		else if (nResponse == IDCANCEL)
		{
			// TODO: Place code here to handle when the dialog is
			//  dismissed with Cancel
		}
		else if (nResponse == -1)
		{
			TRACE(traceAppMsg, 0, "Warning: dialog creation failed, so application is terminating unexpectedly.\n");
			TRACE(traceAppMsg, 0, "Warning: if you are using MFC controls on the dialog, you cannot #define _AFX_NO_MFC_CONTROLS_IN_DIALOGS.\n");
		}
	}

	// Delete the shell manager created above.
	if (pShellManager != NULL)
	{
		delete pShellManager;
	}

#ifndef _AFXDLL
	ControlBarCleanUp();
#endif

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}

