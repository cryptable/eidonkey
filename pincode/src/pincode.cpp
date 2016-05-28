#include <stdio.h>
#include <pincode.h>
#include <PinCodeDlg.h>
#include <wx/wx.h>
#include <wx/init.h> 
#include <wx/app.h>
#include <wx/textdlg.h>

wxDEFINE_EVENT(MY_DIALOGS_TYPE, wxCommandEvent);

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

	    Bind(MY_DIALOGS_TYPE, &MyApp::OnPINCode, this, wxID_ANY);
	}

	void OnPINCode(wxCommandEvent& WXUNUSED(event)) {
		pinCode.Clear();

	    printf("Create PIN Dialog\n");
		PinCodeDlg pinCodeDlg(NULL);
		if (pinCodeDlg.ShowModal() == wxID_OK)
		{
		    printf("PIN Dialog destroyed\n");
			pinCode = pinCodeDlg.GetPassword();

		}
		ExitMainLoop();
	}

};

IMPLEMENT_APP_NO_MAIN(MyApp)

void initPINCode(void) {
	int argc=0;
	char **argv = NULL;
	printf("wxwidgets Init\n");
	wxEntryStart(argc, argv);
	wxGetApp().CallOnInit();
}

unsigned long getPINCode(unsigned int nbrRetries, char *pincode, unsigned long *len) {
	wxString wx_pincode= "";

	if ((*len == 0)||(pincode == NULL)) {
		return PINCODE_BUFFER_UNDEFINED;
	}
	memset((void *)pincode, 0, *len);

	// Call PIN Dialog
	wxCommandEvent event(MY_DIALOGS_TYPE);
	event.SetString("Calling the PinCodeDlg");
	wxPostEvent(&(wxGetApp()), event);
    printf("Entering Process pending events\n");
 	wxGetApp().MainLoop();
    printf("Process pending events ended\n");

	wx_pincode = wxGetApp().GetPinCode();

	printf("PIN code [%s]\n", (const char*)wx_pincode.c_str());
	if (*len < wx_pincode.length()) {
		return PINCODE_BUFFER_TOO_SMALL;
	}
	if (wx_pincode.length() == 0) {
		return PINCODE_NOT_ENTERED;
	}

	*len = wx_pincode.length();
	strncpy(pincode, (const char *)wx_pincode.mb_str(), *len);

	printf("exit get PINCode\n");

	return PINCODE_OK;
}

void closePINCode(void) {
	printf("wxwidgets Cleanup\n");
	wxEntryCleanup();
}