# Account information form

from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email  # V-09 FIX: Email validator added


class The_Accounts(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    # V-09 FIX: Email() validator enforces RFC-compliant email format.
    email = StringField("Email", validators=[DataRequired(), Email()])
    about = TextAreaField("About", validators=[Length(max=385)])
    picture = FileField("Profile picture")
    submit = SubmitField()
