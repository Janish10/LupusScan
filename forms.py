from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL, IPAddress, ValidationError

class URLScanForm(FlaskForm):
    """Form for URL scanning"""
    url = StringField('URL to Scan', validators=[DataRequired(), URL(message="Please enter a valid URL")], 
                      render_kw={"placeholder": "https://example.com"})
    submit = SubmitField('Scan URL')
    
    def validate_url(self, field):
        """Custom URL validation to ensure protocol is included"""
        if not field.data.startswith(('http://', 'https://')):
            raise ValidationError('URL must start with http:// or https://')

class IPScanForm(FlaskForm):
    """Form for IP address scanning"""
    ip = StringField('IP Address to Scan', validators=[DataRequired(), IPAddress(message="Please enter a valid IP address")], 
                     render_kw={"placeholder": "192.168.1.1"})
    submit = SubmitField('Scan IP Address')

class FileScanForm(FlaskForm):
    """Form for file scanning"""
    file = FileField('File to Scan', validators=[
        FileRequired(message="Please select a file"),
        FileAllowed(['txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'exe', 'dll', 'zip'], 
                   'Only allowed file types: txt, pdf, doc, docx, xls, xlsx, exe, dll, zip')
    ])
    submit = SubmitField('Scan File')