/*
 * PinCodeDlg implementation
 */
#include <wx/wx.h>
#include <SignPinCodeDlg.h>
#include <PinCodeVal.h>

#define ID_PIN	0x0001

SignPinCodeDlg::SignPinCodeDlg(wxWindow* parent,
                	           wxWindowID id,
		                       const wxString& caption,
                               int nbrRetries,
                               wxString sHash) : wxDialog(parent, id, caption)
{
    wxBoxSizer *topSizer = new wxBoxSizer( wxVERTICAL );

    // Pre create OK button to give it to the validator
    wxButton* ok = new wxButton ( this, wxID_OK, wxT("&OK"),
        wxDefaultPosition, wxDefaultSize, 0 );
    ok->SetDefault();
    ok->Disable();

    // Add hash to enter 
    wxStaticText* text_descr = new wxStaticText( this, wxID_STATIC, _T("Hash of text:"), wxDefaultPosition, wxDefaultSize, 0);
    topSizer->Add(text_descr, 0, wxALIGN_LEFT|wxALL, 5);
    wxStaticText* text = new wxStaticText( this, wxID_STATIC, sHash, wxDefaultPosition, wxDefaultSize, 0);
    topSizer->Add(text, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

    // Add text to enter the PIN code
    wxStaticText* descr = NULL;
    if (nbrRetries < 0) {
        descr = new wxStaticText( this, wxID_STATIC, _T("Enter PIN code"), wxDefaultPosition, wxDefaultSize, 0 );
    }
    else {
        descr = new wxStaticText( this, wxID_STATIC, wxString::Format(_T("Enter PIN code (%d retries left)"), nbrRetries), wxDefaultPosition, wxDefaultSize, 0 );        
    }
    topSizer->Add(descr, 0, wxALIGN_LEFT|wxALL, 5);

    // TODO add a wxValidator which is able to enable the OK button if 4 to 8 numeric values are entered
    m_PinCtrl = new wxTextCtrl ( this, ID_PIN, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD, PinCodeVal(4, 8, ok));
    topSizer->Add(m_PinCtrl, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);
    
    // Add the Cancel and OK button
    wxBoxSizer* okCancelBox = new wxBoxSizer(wxHORIZONTAL);
    topSizer->Add(okCancelBox, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);
    // The Cancel button
    wxButton* cancel = new wxButton ( this, wxID_CANCEL,
        wxT("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    okCancelBox->Add(cancel, 0, wxALL, 5);
    // The OK button
    okCancelBox->Add(ok, 0, wxALL, 5);

    SetSizer( topSizer );

    topSizer->Fit( this );
    topSizer->SetSizeHints( this );

    Bind(wxEVT_COMMAND_BUTTON_CLICKED, &SignPinCodeDlg::OnOK, this, ok->GetId());
    Bind(wxEVT_COMMAND_BUTTON_CLICKED, &SignPinCodeDlg::OnCancel, this, cancel->GetId());

	Center();
}

void SignPinCodeDlg::OnOK(wxCommandEvent& WXUNUSED(event) )
{
    if (Validate())
    {
        m_sPassword = m_PinCtrl->GetValue();
        if (GetParent()) {
            GetParent()->SetFocus();
        }
        EndModal( wxID_OK );
        Destroy();
    }
}

void SignPinCodeDlg::OnCancel(wxCommandEvent& WXUNUSED(event) )
{
    if (GetParent()) {
        GetParent()->SetFocus();
    }
    EndModal( wxID_CANCEL );
    Destroy();
}