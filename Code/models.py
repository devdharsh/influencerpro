from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    profile_pic = db.Column(db.String(120), nullable=True)
    category = db.Column(db.String(100), nullable=True)
    platform = db.Column(db.String(100), nullable=True)
    campaigns = db.relationship('Campaign', backref='user', lazy=True)
    followers = db.Column(db.Integer, default=0)
    rating = db.Column(db.Integer, default=0)
    mobile = db.Column(db.String(15), unique=True, nullable=True)
    target = db.Column(db.Integer, default=0)
    languages = db.Column(db.String(255), nullable=True)
    content_style = db.Column(db.String(100), nullable=True)
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def get_total_campaigns(self):
        return Campaign.query.filter_by(user_id=self.id).count()

    def get_total_earnings(self):
        campaigns = Campaign.query.filter_by(user_id=self.id).all()
        return sum(campaign.payment for campaign in campaigns)
    
    def get_flag_messages(self):
        # Get flags targeting this user
        user_flags = Flag.query.filter_by(flagged_user_id=self.id).all()

        # Get flags targeting campaigns owned by this user (sponsor)
        campaign_flags = Flag.query.join(Campaign).filter(Campaign.user_id == self.id).all()

        # Combine and sort by timestamp (if needed)
        flag_messages = user_flags + campaign_flags
        flag_messages.sort(key=lambda x: x.timestamp, reverse=True)

        return flag_messages

class Flag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    flagged_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    flagged_by = db.relationship('User', foreign_keys=[flagged_by_id], backref='flags')
    flagged_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    flagged_user = db.relationship('User', foreign_keys=[flagged_user_id], backref='flagged_by')
    flagged_campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=True)
    flagged_campaign = db.relationship('Campaign', backref='flags')
    reason = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())


    def __repr__(self):
        return f'<Flag {self.id}>'


class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200), nullable=True)
    niche = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date=db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')
    budget=db.Column(db.Integer,unique=True)
    payment=db.Column(db.Integer, unique=True)

    def __repr__(self):
        return f'<Campaign {self.title}>'
    
class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('requests', lazy=True))
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    campaign = db.relationship('Campaign', backref=db.backref('requests', lazy=True))
    status = db.Column(db.String(50), nullable=False, default='pending')

def get_active_campaigns(user_id):
    # Query the database for active campaigns associated with the given user_id
    campaigns = Campaign.query.filter_by(user_id=user_id).all()

    # Return an empty list if no campaigns are found
    return campaigns if campaigns is not None else []


