/*
 * PinCodeDlg implementation
 */
#include <wx/wx.h>
#include <PinCodeDlg.h>
#include <PinCodeVal.h>

#define ID_PIN	0x0001

PinCodeDlg::PinCodeDlg(wxWindow* parent,
                	   wxWindowID id,
		               const wxString& caption) : wxDialog(parent, id, caption)
{
    wxBoxSizer *topSizer = new wxBoxSizer( wxVERTICAL );

    // Pre create OK button to give it to the validator
    wxButton* ok = new wxButton ( this, wxID_OK, wxT("&OK"),
        wxDefaultPosition, wxDefaultSize, 0 );
    ok->SetDefault();
    ok->Disable();

    // Add text to enter the PIN code
    wxStaticText* descr = new wxStaticText( this, wxID_STATIC, _T("Enter PIN code"), wxDefaultPosition, wxDefaultSize, 0 );
    topSizer->Add(descr, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

    // TODO add a wxValidator which is able to enable the OK button if 4 to 8 numeric values are entered
    m_PinCtrl = new wxTextCtrl ( this, ID_PIN, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD, PinCodeVal(4, 8, ok));
//    m_PinCtrl = new wxTextCtrl ( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD);
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

    Bind(wxEVT_COMMAND_BUTTON_CLICKED, &PinCodeDlg::OnOK, this, ok->GetId());
    Bind(wxEVT_COMMAND_BUTTON_CLICKED, &PinCodeDlg::OnCancel, this, cancel->GetId());

	Center();
}

void PinCodeDlg::OnOK(wxCommandEvent& WXUNUSED(event) )
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

void PinCodeDlg::OnCancel(wxCommandEvent& WXUNUSED(event) )
{
    if (GetParent()) {
        GetParent()->SetFocus();
    }
    EndModal( wxID_CANCEL );
    Destroy();
}