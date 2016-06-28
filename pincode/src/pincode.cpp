#include <stdio.h>
#include <pincode.h>
#include <PinCodeDlg.h>
#include <wx/wx.h>
#include <wx/init.h> 
#include <wx/app.h>
#include <wx/textdlg.h>

wxDEFINE_EVENT(PINCODE_AUTH_DIALOG, wxCommandEvent);
wxDEFINE_EVENT(PINCODE_SIGN_DIALOG, wxCommandEvent);

class MyApp : public wxApp
{
private:
	wxString pinCode;

public:
	wxString GetPinCode() {
		return pinCode;
	}

	virtual bool OnInit() {
	    if ( !wxApp::OnInit() )
	        return false;

	    Bind(PINCODE_AUTH_DIALOG, &MyApp::OnAuthPINCode, this, wxID_ANY);
	    Bind(PINCODE_SIGN_DIALOG, &MyApp::OnSignPINCode, this, wxID_ANY);
	}

	void OnAuthPINCode(wxCommandEvent& WXUNUSED(event)) {
		pinCode.Clear();

		wxWindow* parent = wxGetActiveWindow();

		PinCodeDlg pinCodeDlg(parent, wxID_ANY, wxT("Authentication PIN"));
		if (pinCodeDlg.ShowModal() == wxID_OK)
		{
			pinCode = pinCodeDlg.GetPassword();

		}
		if (parent) {
			parent->SetFocus();
		}
		ExitMainLoop();
	}

	void OnSignPINCode(wxCommandEvent& WXUNUSED(event)) {
		pinCode.Clear();

		wxWindow* parent = wxGetActiveWindow();

		PinCodeDlg pinCodeDlg(parent, wxID_ANY, wxT("Signing PIN"));
		if (pinCodeDlg.ShowModal() == wxID_OK)
		{
			pinCode = pinCodeDlg.GetPassword();

		}
		if (parent) {
			parent->SetFocus();
		}
		ExitMainLoop();
	}

};

IMPLEMENT_APP_NO_MAIN(MyApp)

void initPINCode(void) {
	int argc=0;
	char **argv = NULL;
	wxEntryStart(argc, argv);
	wxGetApp().CallOnInit();
}

unsigned long getAuthenticationPINCode(unsigned int nbrRetries, char *pincode, unsigned long *len) {
	wxString wx_pincode= "";

	if ((*len == 0)||(pincode == NULL)) {
		return PINCODE_BUFFER_UNDEFINED;
	}
	memset((void *)pincode, 0, *len);

	// Call PIN Dialog
	wxCommandEvent event(PINCODE_AUTH_DIALOG);
	wxPostEvent(&(wxGetApp()), event);
 	wxGetApp().MainLoop();

	wx_pincode = wxGetApp().GetPinCode();

	if (*len < wx_pincode.length()) {
		return PINCODE_BUFFER_TOO_SMALL;
	}
	if (wx_pincode.length() == 0) {
		return PINCODE_NOT_ENTERED;
	}

	*len = wx_pincode.length();
	strncpy(pincode, (const char *)wx_pincode.mb_str(), *len);

	return PINCODE_OK;
}

unsigned long getSigningPINCode(unsigned int nbrRetries, char *pincode, unsigned long *len) {
	wxString wx_pincode= "";

	if ((*len == 0)||(pincode == NULL)) {
		return PINCODE_BUFFER_UNDEFINED;
	}
	memset((void *)pincode, 0, *len);

	// Call PIN Dialog
	wxCommandEvent event(PINCODE_SIGN_DIALOG);
	wxPostEvent(&(wxGetApp()), event);
 	wxGetApp().MainLoop();

	wx_pincode = wxGetApp().GetPinCode();

	if (*len < wx_pincode.length()) {
		return PINCODE_BUFFER_TOO_SMALL;
	}
	if (wx_pincode.length() == 0) {
		return PINCODE_NOT_ENTERED;
	}

	*len = wx_pincode.length();
	strncpy(pincode, (const char *)wx_pincode.mb_str(), *len);

	return PINCODE_OK;
}

void closePINCode(void) {
	wxEntryCleanup();
}