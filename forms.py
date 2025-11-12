from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Optional, ValidationError
import re


_SQLI_PATTERN = re.compile(r"\b(select|insert|update|delete|drop|truncate|union|--|;|/\*|\*/|xp_)\b", re.IGNORECASE)
_SCRIPT_TAG_PATTERN = re.compile(r"<\s*/?\s*script\b", re.IGNORECASE)


def reject_malicious_text(message: str = "Invalid input."):
    def _validator(form, field):
        value = (field.data or "").strip()
        if _SQLI_PATTERN.search(value) or _SCRIPT_TAG_PATTERN.search(value):
            raise ValidationError(message)
    return _validator


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80), reject_malicious_text("Username contains invalid patterns.")])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=128)])
    submit = SubmitField("Login")


class PersonForm(FlaskForm):
    first_name = StringField("First name", validators=[DataRequired(), Length(max=100), reject_malicious_text("First name contains invalid patterns.")])
    last_name = StringField("Last name", validators=[Optional(), Length(max=100), reject_malicious_text("Last name contains invalid patterns.")])
    email = StringField("Email", validators=[Optional(), Email(), Length(max=120)])
    # message is optional for index/update; used in contact form specifically
    message = TextAreaField("Message", validators=[Optional(), Length(max=2000), reject_malicious_text("Message contains invalid patterns.")])
    submit = SubmitField("Submit")


class ContactForm(FlaskForm):
    first_name = StringField("First name", validators=[DataRequired(), Length(max=100), reject_malicious_text("First name contains invalid patterns.")])
    last_name = StringField("Last name", validators=[Optional(), Length(max=100), reject_malicious_text("Last name contains invalid patterns.")])
    email = StringField("Email", validators=[Optional(), Email(), Length(max=120)])
    message = TextAreaField("Message", validators=[Optional(), Length(max=2000), reject_malicious_text("Message contains invalid patterns.")])
    submit = SubmitField("Save Contact")


