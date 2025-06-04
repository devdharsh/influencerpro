from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, DateField, SubmitField,SelectField,IntegerField
from wtforms.validators import DataRequired, Length

class CampaignForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    image = FileField('Image')
    end_date=DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    niche = StringField('Niche', validators=[DataRequired(), Length(max=100)])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Add Campaign')
    budget = IntegerField('Budget', validators=[DataRequired()])
    payment=IntegerField('Payment for an Advertisement',validators=[DataRequired()])
    niche = SelectField(
        'Category',
        choices=[
            ('beauty and fashion', 'Beauty and Fashion'),
            ('gaming', 'Gaming'),
            ('lifestyle', 'Lifestyle'),
            ('tech', 'Tech'),
            ('education', 'Educational'),
            ('food', 'Food'),
            ('travel', 'Travel')
        ],
        validators=[DataRequired()],
        render_kw={"class": "form-control"}
    )
class RequestForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    campaign_id = IntegerField('Campaign ID', validators=[DataRequired()])
    submit = SubmitField('Create Request')