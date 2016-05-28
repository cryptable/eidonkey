/*
 * PIN code Validator implementation
 */
#include "wx/wx.h"
#include "PinCodeVal.h"

PinCodeVal::PinCodeVal(int minLength, int maxLength, wxButton *button)
{
	m_minLength = minLength;
	m_maxLength = maxLength;
	m_button =  button;

    Bind(wxEVT_COMMAND_TEXT_UPDATED, &PinCodeVal::OnChar, this, wxID_ANY);
}

PinCodeVal::PinCodeVal(const PinCodeVal& val) : wxValidator()
{
	Copy(val);
}

bool PinCodeVal::Copy(const PinCodeVal& val)
{
    wxValidator::Copy(val);

    m_button = val.m_button;

    m_minLength    = val.m_minLength;
    m_maxLength    = val.m_maxLength;

    Bind(wxEVT_COMMAND_TEXT_UPDATED, &PinCodeVal::OnChar, this, wxID_ANY);
    return true;
}

// ----------------------------------------------------------------------------
// global helpers
// ----------------------------------------------------------------------------

bool PinCodeVal::IsNumeric(const wxString& val)
{
    for ( wxString::const_iterator i = val.begin(); i != val.end(); ++i )
    {
        if (!wxIsdigit(*i)) {
            return false;
        }
    }
    return true;
}

bool PinCodeVal::Validate(wxWindow *parent)
{
    // If window is disabled, simply return
    if ( !m_validatorWindow->IsEnabled() )
        return true;

	wxTextEntry* text = NULL;
    if (wxDynamicCast(m_validatorWindow, wxTextCtrl))
    {
        text = (wxTextCtrl*)m_validatorWindow;
    }
    else
	{
		return false;
	}

    wxString val(text->GetValue());

    wxString errormsg;

    // Value empty
    if (val.length() < m_minLength) {
    	errormsg = _("number characters of PIN code too small");
    }
    else if (val.length() > m_maxLength) {
    	errormsg = _("number characters of PIN code too big");
    }
    else if (!IsNumeric(val)) {
    	errormsg = _("PIN code contains non digit characters");    	
    }

    if ( !errormsg.empty() )
    {
        m_validatorWindow->SetFocus();
        wxMessageBox(errormsg, _("Validation conflict"),
                     wxOK | wxICON_EXCLAMATION, parent);

        return false;
    }

    return true;
}

// Called to transfer data to the window
bool PinCodeVal::TransferToWindow()
{
	wxTextEntry* text = NULL;

    if (wxDynamicCast(m_validatorWindow, wxTextCtrl))
    {
        text = (wxTextCtrl*)m_validatorWindow;
    }
    else
	{
		return false;
	}

    text->SetValue(m_value);

    return true;
}

// Called to transfer data to the window
bool PinCodeVal::TransferFromWindow()
{
	wxTextEntry* text = NULL;

    if (wxDynamicCast(m_validatorWindow, wxTextCtrl))
    {
        text = (wxTextCtrl*)m_validatorWindow;
    }
    else
	{
		return false;
	}


    m_value = text->GetValue();

    return true;
}

void PinCodeVal::OnChar(wxCommandEvent& event)
{
    wxKeyEvent &eventKey = (wxKeyEvent &)event;

    if (!m_validatorWindow)
    {
        event.Skip();
        return;
    }

	wxTextEntry* text = NULL;

    if (wxDynamicCast(m_validatorWindow, wxTextCtrl))
    {
        text = (wxTextCtrl*)m_validatorWindow;
    }
    else
	{
		return;
	}
    wxString value = text->GetValue();

    if (text->GetValue().length() > m_maxLength)
    {
        text->SetValue(m_value);
        text->SetInsertionPoint(m_value.length());
    	return;
    }

    if (!IsNumeric(value))
    {
        if ( !wxValidator::IsSilent() )
            wxBell();

        text->SetValue(m_value);
        text->SetInsertionPoint(m_value.length());
        // eat message
        return;
    }
    else
    {
        m_value = value;
	    if (m_button && (value.length() >= m_minLength)) {
	    	m_button->Enable();
	    }
        else {
            m_button->Disable();            
        }
        event.Skip();
    }

}

