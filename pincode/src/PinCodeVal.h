#ifndef PINCODEVAL_H
#define PINCODEVAL_H
/*
 * PIN code Validator
 */
#include <wx/wx.h>

class PinCodeVal: public wxValidator
{
public:
    PinCodeVal(int minLength = 4, int maxLength = 8, wxButton *button = NULL);
    PinCodeVal(const PinCodeVal& val);

	virtual ~PinCodeVal(){}

	// Clone member function
    virtual wxObject *Clone() const { return new PinCodeVal(*this); }

    bool Copy(const PinCodeVal& val);

    // Called when the value in the window must be validated.
    // This function can pop up an error message.
    virtual bool Validate(wxWindow *parent);

    // Called to transfer data to the window
    virtual bool TransferToWindow();

    // Called to transfer data from the window
    virtual bool TransferFromWindow();

    // Filter keystrokes
    void OnChar(wxCommandEvent& event);

protected:
	int m_minLength;
	int m_maxLength;
	wxButton *m_button;
    wxString m_value;

private:
	static bool IsNumeric(const wxString& val);

};
#endif // PINCODEVAL_H