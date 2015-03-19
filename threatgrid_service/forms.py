from django import forms

class ThreatGRIDConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    api_key = forms.CharField(required=True,
                                label="API Key",
                                widget=forms.TextInput(),
                                help_text="Obtain an API key from a ThreatGRID device.",
                                initial='')
    host = forms.CharField(required=True,
                                label="ThreatGRID URL",
                                widget=forms.TextInput(),
                                initial='https://threatgrid.com/')

    def __init__(self, *args, **kwargs):
        super(ThreatGRIDConfigForm, self).__init__(*args, **kwargs)
