#include <stdio.h>
#include <pincode.h>
#include <PinCodeDlg.h>
#include <SignPinCodeDlg.h>
#include <wx/wx.h>
#include <wx/init.h> 
#include <wx/app.h>
#include <wx/textdlg.h>

wxDEFINE_EVENT(AUTHENTICATION_PIN_DIALOGS_TYPE, wxCommandEvent);
wxDEFINE_EVENT(SIGNATURE_PIN_DIALOGS_TYPE, wxCommandEvent);

class MyApp : public wxApp
{
private:
	wxString pinCode;
	long	 nbrRetries;
	wxString hash;

public:
	void SetNbrRetries(long retries) {
		this->nbrRetries = retries;
	}

	void SetHash(char *h) {
		this->hash = h;
	}

	wxString GetPinCode() {
		return pinCode;
	}

	virtual bool OnInit() {
		nbrRetries = -1;

	    if ( !wxApp::OnInit() )
	        return false;

	    Bind(AUTHENTICATION_PIN_DIALOGS_TYPE, &MyApp::OnAuthenticationPINCode, this, wxID_ANY);
	    Bind(SIGNATURE_PIN_DIALOGS_TYPE, &MyApp::OnSignaturePINCode, this, wxID_ANY);
	    return true;
	}

	void OnAuthenticationPINCode(wxCommandEvent& WXUNUSED(event)) {
		pinCode.Clear();

		wxWindow* parent = wxGetActiveWindow();

		PinCodeDlg pinCodeDlg(parent, wxID_ANY, wxT("Authentication PIN code"), nbrRetries);
		if (pinCodeDlg.ShowModal() == wxID_OK)
		{
			pinCode = pinCodeDlg.GetPassword();

		}
		if (parent) {
			parent->SetFocus();
		}
		ExitMainLoop();
	}

	void OnSignaturePINCode(wxCommandEvent& WXUNUSED(event)) {
		pinCode.Clear();

		wxWindow* parent = wxGetActiveWindow();

		SignPinCodeDlg signPINCodeDlg(parent, wxID_ANY, wxT("Signature PIN code"), nbrRetries, hash);
		if (signPINCodeDlg.ShowModal() == wxID_OK)
		{
			pinCode = signPINCodeDlg.GetPassword();

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
	wxGetApp().SetNbrRetries(nbrRetries);
	wxCommandEvent event(AUTHENTICATION_PIN_DIALOGS_TYPE);
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

unsigned long getSignaturePINCode(unsigned int nbrRetries, char *hash, char *pincode, unsigned long *len) {
	wxString wx_pincode= "";

	if ((*len == 0)||(pincode == NULL)) {
		return PINCODE_BUFFER_UNDEFINED;
	}
	memset((void *)pincode, 0, *len);

	// Call PIN Dialog
	wxGetApp().SetNbrRetries(nbrRetries);
	wxGetApp().SetHash(hash);
	wxCommandEvent event(SIGNATURE_PIN_DIALOGS_TYPE);
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