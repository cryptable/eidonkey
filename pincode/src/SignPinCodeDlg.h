#ifndef SIGNPINCODEDLG_H
#define SIGNPINCODEDLG_H

/*
 * PinCodeDialog class declaration
 */
#include <wx/wx.h>

class SignPinCodeDlg: public wxDialog
{    
private:
    wxWindow* m_myParent;

    wxString m_sText;

    wxString m_sHash;

    wxString m_sPassword;

    wxTextCtrl* m_PinCtrl;

public:

    wxString GetPassword()
    {
        return m_sPassword;
    }

    // Constructors
    SignPinCodeDlg( wxWindow* parent,
        wxWindowID id = wxID_ANY,
        const wxString& caption = wxT("Signature PIN code"),
        int nbrRetries = -1,
        wxString sHash = wxT("Missing Hash Value"));
    
    virtual ~SignPinCodeDlg()
    {
    }

    // implementation only
    void OnOK(wxCommandEvent& event);
    void OnCancel(wxCommandEvent& event);

private:

};
#endif // SIGNPINCODEDLG_H