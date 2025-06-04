from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import  User, Campaign, Request, db, Flag
from datetime import datetime
import os, json
from forms import CampaignForm
from sqlalchemy import func


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads/profile_pics'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
db.init_app(app)

# Ensure UPLOAD_FOLDER exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        user = User.query.filter_by(username=username, role=role).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role

            if user.role == 'sponsor':
                return redirect(url_for('sponsor_dashboard'))
            elif user.role == 'influencer':
                return redirect(url_for('influencer_dashboard'))
        else:
            flash('Invalid username, password, or role','error')

    return render_template('login.html')
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/find', methods=['GET', 'POST'])
def find_campaigns():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))
    
    query = Campaign.query
    if request.method == 'POST':
        # Check if the request is for finding campaigns or submitting a request
        if 'campaign_id' in request.form:
            # Handle request submission
            campaign_id = request.form.get('campaign_id')
            message = request.form.get('message')
            
            new_request = Request(
                title="Request to join {{'campaign.title'}} by {{'user.id'}}",  # You can customize this title
                message=message,
                user_id=user.id,
                campaign_id=campaign_id
            )
            db.session.add(new_request)
            db.session.commit()

            flash('Request sent successfully!', 'success')
            return redirect(url_for('find_campaigns'))

        # Handle campaign filtering
        niche = request.form.get('niche')
        date = request.form.get('date')

        if niche:
            query = query.filter(Campaign.niche.ilike(f'%{niche}%'))
        if date:
            query = query.filter(Campaign.start_date == date)

    campaigns = query.all()
    

    influencers = User.query.filter_by(role='influencer').all()
    sponsors = User.query.filter_by(role='sponsor').all()

    return render_template('find.html', campaigns=campaigns, user=user, influencers=influencers, sponsors=sponsors)

@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    # Fetch the influencer based on user_id
    user = User.query.get(user_id)
    if user is None:
        flash('User not found.', 'danger')
        return redirect(url_for('sponsor_dashboard'))
    influencer = User.query.filter_by(role='influencer').all()
    sponsor=User.query.filter_by(role='sponsor').all
    # Fetch the campaigns associated with this influencer
    campaigns = Campaign.query.filter_by(user_id=user.id).all()

    return render_template('view_profile.html', influencer=influencer, campaigns=campaigns,user=user, sponsor=sponsor)
def get_sponsors():
    return User.query.filter_by(role='sponsor').all()

 
@app.route('/profile')
def profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    # Initialize new_requests
    new_requests = []

    # Fetch active campaigns based on user role
    if user.role == 'influencer':
        active_campaigns = Campaign.query.filter(
            Campaign.status == 'active'
        ).all()

        # Fetch new requests related to the influencer
        new_requests = Request.query.filter(
            Request.user_id == user.id,
            Request.status == 'pending'
        ).all()

    elif user.role == 'sponsor':
        active_campaigns = Campaign.query.filter(
            Campaign.status == 'active'
        ).all()
        
        # Fetch new requests related to campaigns created by this sponsor
        new_requests = Request.query.join(Campaign).filter(
            Campaign.user_id == user.id,
            Request.status == 'pending'
        ).all()
    else:
        active_campaigns = []

    now = datetime.now()
    return render_template('profile.html', user=user, active_campaigns=active_campaigns, new_requests=new_requests, now=now)
@app.route('/update_profile', methods=['POST'])
def update_profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    # Get form data
    username = request.form.get('username')
    email = request.form.get('email')
    mobile = request.form.get('mobile', '')
    target = request.form.get('target', '')
    rating = request.form.get('rating', '')
    followers = request.form.get('followers', '')
    languages=request.form.get('languages','')
    
    # Profile Picture Handling
    profile_pic = request.files.get('profile_pic')
    if profile_pic:
        filename = secure_filename(profile_pic.filename)
        file_path = os.path.join('static/uploads/profile_pics', filename)
        profile_pic.save(file_path)
        user.profile_pic = filename

    # Update user details
    user.username = username
    user.email = email
    if user.role == 'sponsor':
        user.mobile = mobile
        user.target = target
    else:
        user.rating = rating
        user.followers = followers
        user.languages=languages

    db.session.commit()

    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/admin_dashboard/info')
def admin_dashboard_info():
    # Fetch active campaigns - assuming campaigns with 'active' status are ongoing
    ongoing_campaigns = Campaign.query.filter_by(status = 'active').all()
    flagged_items = Flag.query.all()
    # Fetch flagged campaigns - assuming flagged campaigns have a specific status
    now =datetime.now()
    # You could also include logic for flagged users, depending on your application logic

    return render_template('admin_dashboard_info.html', 
                           ongoing_campaigns=ongoing_campaigns, 
                           flagged_items=flagged_items, now=now)

@app.route('/admin_dashboard/find', methods=['GET', 'POST'])
def admin_dashboard_find():
    if request.method == 'POST':
        search_query = request.form.get('search_input')
        if search_query:
            # Example: search for users or campaigns based on the query
            search_results = User.query.filter(User.username.ilike(f'%{search_query}%')).all()
            campaign_results = Campaign.query.filter(Campaign.title.ilike(f'%{search_query}%')).all()

            # Combine results or separate as needed
            results = search_results + campaign_results
        else:
            results = []  # No results if the search query is empty

        return render_template('admin_dashboard.html', 
                               search_results=results, 
                               active_section='find-section')

    # Default: render the find section with no search results
    return render_template('admin_dashboard.html', 
                           search_results=[], 
                           active_section='find-section')

@app.route('/stats')
def stats():
    user_id = session.get('user_id') # Replace with the current user's ID, e.g., `current_user.id` if using Flask-Login
    user = User.query.get(user_id)
    
    platform_data = db.session.query(
        User.platform, func.count(User.platform)
    ).group_by(User.platform).all()
    
    category_data = db.session.query(
        User.category, func.count(User.category)
    ).group_by(User.category).all()  # Fixed: added parentheses here
    
    labels_cat = [data[0] for data in category_data]
    values_cat = [data[1] for data in category_data]
    labels = [data[0] for data in platform_data]
    values = [data[1] for data in platform_data]
    
    labels_json = json.dumps(labels)
    values_json = json.dumps(values)
    labels_json_cat = json.dumps(labels_cat)
    values_json_cat = json.dumps(values_cat)
    
    if user:
        total_earnings = db.session.query(func.sum(Campaign.payment)).filter_by(status='active').scalar()
        total_campaigns = Campaign.query.filter_by(status='active').count()
        total_influencers = db.session.query(func.count(User.id)).filter_by(role='influencer').scalar()
        total_sponsors = db.session.query(func.count(User.id)).filter_by(role='sponsor').scalar()
        campaigns = Campaign.query.filter_by(user_id=user.id).all()

        # Prepare data for Chart.js
        campaign_titles = [campaign.title for campaign in campaigns]
        campaign_earnings = [campaign.payment for campaign in campaigns]

        return render_template('stats.html', 
                               user=user, 
                               stats={
                                   'total_earnings': total_earnings, 
                                   'total_campaigns': total_campaigns,
                                   'total_influencers': total_influencers,
                                   'total_sponsors': total_sponsors
                               },
                               campaign_titles=campaign_titles,
                               campaign_earnings=campaign_earnings,
                               labels=labels_json,
                               values=values_json,
                               labels_cat=labels_json_cat,
                               values_cat=values_json_cat)
    else:
        # Handle case when user is not found (optional)
        return "User not found", 404    
@app.route('/sponsor_dashboard', methods=['GET', 'POST'])
def sponsor_dashboard():
    if 'username' in session:
        user = User.query.filter_by(username=session['username'], role='sponsor').first()
        
        if user:
            flagged_campaigns = Flag.query.filter_by(flagged_campaign_id=Campaign.id).join(Campaign).filter(Campaign.user_id == user.id).all()
            
            flagged_users = Flag.query.filter_by(flagged_user_id=user.id).all()

            flag_messages = flagged_campaigns + flagged_users

            return render_template('sponsor_dashboard.html', user=user, flag_messages=flag_messages)
        else:
            return "Sponsor not found", 404
    else:
        return "Unauthorized", 401

@app.route('/influencer_dashboard', methods=['GET', 'POST'])
def influencer_dashboard():
    if 'username' in session:
        user = User.query.filter_by(username=session['username'], role='influencer').first()
        
        if user:
            flag_messages = Flag.query.filter(
                (Flag.flagged_user_id == user.id) |
                (Flag.flagged_campaign.has(user_id=user.id))
            ).all()
            
            return render_template('influencer_dashboard.html', user=user, flag_messages=flag_messages)
        else:
            return "Influencer not found", 404
    else:
        return "Unauthorized", 401


import logging
@app.route('/register_influencer', methods=['GET', 'POST'])
def register_influencer():
    if request.method == 'POST':
        # Collect form data
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        category = request.form['category']
        platform = request.form['platform']
        followers = request.form['followers']
        rating = request.form['rating']
        mobile = request.form['mobile']
        languages = request.form['languages']
        content_style = request.form['content_style']

        # Profile Picture Handling
        profile_pic = request.files.get('profile_pic')
        filename = None
        if profile_pic:
            # Use secure_filename to avoid issues with file names
            filename = secure_filename(profile_pic.filename)
            file_path = os.path.join('static/uploads/profile_pics', filename)
            # Save the file to the specified path
            profile_pic.save(file_path)

        # Create user with role 'influencer'
        new_user = User(
            username=username,
            email=email,
            role='influencer',
            profile_pic=filename,  # Assign the profile picture filename here
            category=category,
            platform=platform,
            followers=followers,
            rating=rating,
            mobile=mobile,
            languages=languages,
            content_style=content_style
        )
        new_user.set_password(password)

        # Save the new user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Influencer registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('influencer_registration.html')

@app.route('/view_campaign_details/<int:campaign_id>', methods=['GET'])
def view_campaign_details(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    if campaign is None:
        abort(404)
    
    user_id = session.get('user_id')
    user = User.query.get(user_id)
  
    new_requests = Request.query.join(Campaign).filter(
            Campaign.user_id == user.id  # Campaigns created by this sponsor
        )
    # Check if new_requests is populated
    if not new_requests:
        print("No requests found.")
    
    return render_template('view_campaign_details.html', campaign=campaign, user=user, new_requests=new_requests)
@app.route('/campaign/<int:campaign_id>', methods=['GET'])
def view_campaign(campaign_id):
    # Retrieve the campaign details from the database
    campaign = Campaign.query.get(campaign_id)
    now = datetime.now()
    # If no campaign is found, return a 404 error
    if campaign is None:
        abort(404)
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    # Pass the campaign details to the template
    return render_template('view_campaign.html', campaign=campaign, now=now, user=user)
@app.route('/request_influencer', methods=['POST'])
def request_influencer():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    campaign_id = request.form.get('campaign_id')
    message = request.form.get('message')

    print(f"Campaign ID: {campaign_id}")
    print(f"Message: {message}")

    if user and campaign_id and message:
        new_request = Request(title=f'Request to join Campaign', status='pending', user_id=user.id, campaign_id=campaign_id, message=message)
        db.session.add(new_request)
        db.session.commit()
        flash('Request sent successfully!', 'success')
    else:
        flash('Failed to send request. Please try again.', 'danger')

    return redirect(url_for('find_campaigns'))
from flask import request, jsonify
@app.route('/negotiate_request', methods=['POST'])
def negotiate_request():
    request_id = request.form.get('request_id')
    if not request_id:
        flash('Invalid request.', 'danger')
        return redirect(url_for('profile'))

    req = Request.query.get(request_id)
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('profile'))

    req.status = 'negotiated'
    db.session.commit()

    flash('Request accepted successfully!', 'success')
    return redirect(url_for('profile'))
@app.route('/accept_request', methods=['POST'])
def accept_request():
    request_id = request.form.get('request_id')
    if not request_id:
        flash('Invalid request.', 'danger')
        return redirect(url_for('profile'))

    req = Request.query.get(request_id)
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('profile'))

    req.status = 'accepted'
    db.session.commit()

    flash('Request accepted successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/reject_request', methods=['POST'])
def reject_request():
    request_id = request.form.get('request_id')
    if not request_id:
        flash('Invalid request.', 'danger')
        return redirect(url_for('profile'))

    req = Request.query.get(request_id)
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('profile'))

    req.status = 'rejected'
    db.session.commit()

    flash('Request rejected successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/get_messages', methods=['GET'])
def get_messages():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    # Fetch flags related to the user
    flags = Flag.query.filter(
        (Flag.flagged_by_id == user_id) | (Flag.flagged_user_id == user_id)
    ).all()

    messages = [
        {
            'title': f'Flagged {flag.flagged_user.username if flag.flagged_user else "Unknown User"}' 
                     if flag.flagged_by_id == user_id 
                     else f'Flagged Campaign {flag.flagged_campaign.title if flag.flagged_campaign else "Unknown Campaign"}',
            'message': flag.reason
        }
        for flag in flags
    ]

    return jsonify({'messages': messages})
@app.route('/remove_item', methods=['POST'])
def remove_item():
    user_id = request.form.get('user_id')
    campaign_id = request.form.get('campaign_id')
    
    # Ensure at least one of user_id or campaign_id is provided
    if user_id:
        user = User.query.get(user_id)
        if user:
            # Implement logic to remove user or mark as removed
            db.session.delete(user)
            db.session.commit()
            flash("User removed successfully.", "success")
        else:
            flash("User not found.", "danger")
    
    if campaign_id:
        campaign = Campaign.query.get(campaign_id)
        if campaign:
            # Implement logic to remove campaign or mark as removed
            db.session.delete(campaign)
            db.session.commit()
            flash("Campaign removed successfully.", "success")
        else:
            flash("Campaign not found.", "danger")
    
    return redirect(url_for('find_campaigns'))
@app.route('/campaigns', methods=['GET', 'POST'])
def campaigns():
    form = CampaignForm()
    user_id = session.get('user_id')  # Get the user ID from session

    if user_id is None:
        flash('You must be logged in to access this page.','info')
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    if form.validate_on_submit():
        image_filename = None
        if form.image.data:
            image_filename = secure_filename(form.image.data.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            form.image.data.save(image_path)

        new_campaign = Campaign(
            title=form.title.data,
            description=form.description.data,
            image=image_filename,
            niche=form.niche.data,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            user_id=user_id,  # Use the actual user ID from session
            status='active',
            payment=form.payment.data,
            budget=form.budget.data
        )
        db.session.add(new_campaign)
        db.session.commit()
        flash('Campaign added successfully!','success')
        return redirect(url_for('campaigns'))

    # Fetch the campaigns for the user to display on the page
    active_campaigns = Campaign.query.filter_by(user_id=user_id).all()
    return render_template('campaigns.html', form=form, user=user, active_campaigns=active_campaigns)

def get_influencers():
    # Query the database for users with the role 'influencer'
    influencers = User.query.filter_by(role='influencer').all()
    return influencers

@app.route('/create_ad_request/<int:campaign_id>', methods=['GET', 'POST'])
def create_ad_request(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    user_id = session.get('user_id')
    
    if user_id is None:
        flash('You must be logged in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(user_id)
    influencers = User.query.filter_by(role='influencer').all()

    if request.method == 'POST':
        influencer_id = request.form.get('influencer')
        message = request.form.get('message')
        influencer = User.query.get(influencer_id)

        if influencer and message:
            try:
                new_request = Request(
                    title=campaign.title,
                    message=message,
                    user_id=influencer.id,
                    campaign_id=campaign.id,
                    status='pending'
                )
                db.session.add(new_request)
                db.session.commit()
                flash('Ad Request created successfully!', 'success')
                return redirect(url_for('profile'))
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred: {str(e)}', 'danger')
        else:
            flash('Influencer or message not found. Please ensure all fields are filled correctly.', 'danger')
    
    return render_template('create_ad_request.html', campaign=campaign, user=user, influencers=influencers)
@app.route('/register_sponsor', methods=['GET', 'POST'])
def register_sponsor():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        category = request.form['category']
        platform = request.form['platform']
        target = request.form['target']
        mobile = request.form['mobile']

        # Profile Picture Handling
        profile_pic = request.files.get('profile_pic')
        filename = None
        if profile_pic:
            filename = secure_filename(profile_pic.filename)
            file_path = os.path.join('static/uploads/profile_pics', filename)
            profile_pic.save(file_path)

        # Create user with role 'sponsor'
        new_user = User(
            username=username,
            email=email,
            role='sponsor',
            profile_pic=filename,  # Assign the profile picture filename here
            category=category,
            platform=platform,
            target=target,
            mobile=mobile
        )
        new_user.set_password(password)

        # Save the new user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Sponsor registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('sponsor_registration.html')
@app.route('/flag', methods=['POST'])
def flag():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    flagged_by_id = user.id
    flagged_user_id = request.form.get('flagged_user_id')
    flagged_campaign_id = request.form.get('flagged_campaign_id')
    reason = request.form.get('reason')

    # Debugging information
    print(f"Flagged By ID: {flagged_by_id}")
    print(f"Flagged User ID: {flagged_user_id}")
    print(f"Flagged Campaign ID: {flagged_campaign_id}")
    print(f"Reason: {reason}")

    if not flagged_user_id and not flagged_campaign_id:
        flash('No user or campaign specified for flagging.', 'danger')
        return redirect(url_for('find_campaigns'))

    new_flag = Flag(
        flagged_by_id=flagged_by_id,
        flagged_user_id=flagged_user_id if flagged_user_id else None,
        flagged_campaign_id=flagged_campaign_id if flagged_campaign_id else None,
        reason=reason
    )
    db.session.add(new_flag)
    db.session.commit()

    flash('Flag has been submitted successfully.', 'success')
    return redirect(url_for('find_campaigns'))
@app.route('/remove_flag/<int:flag_id>')
def remove_flag(flag_id):
    flag = Flag.query.get(flag_id)
    if flag:
        db.session.delete(flag)
        db.session.commit()
        flash('Flag removed successfully.', 'success')
    else:
        flash('Flag not found.', 'danger')
    return redirect(url_for('admin_dashboard_info'))

def get_flagged_campaigns():
    # Define the logic to fetch flagged campaigns
    # For example, you might filter by status or some other criteria
    return Campaign.query.filter_by(status='flagged').all()
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'role' in session and session['role'] == 'admin':
        user = User.query.filter_by(username='admin', role='admin').first()
        admin_name = 'admin'  # Use dynamic user info
        active_campaigns = Campaign.query.filter_by(status='active').all()
        flagged_campaigns = get_flagged_campaigns()  # Adjust this function to your needs
        search_results = []  
        now = datetime.now()

        return render_template('admin_dashboard.html',
                               user=user,
                               admin_name=admin_name,
                               active_campaigns=active_campaigns,
                               flagged_campaigns=flagged_campaigns,
                               search_results=search_results,
                               now=now)
    else:
        return "Unauthorized", 401

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Retrieve admin user from the database
        admin_user = User.query.filter_by(username=username, role='admin').first()

        if admin_user and check_password_hash(admin_user.password, password):
            session['user_id'] = admin_user.id
            session['username'] = admin_user.username
            session['role'] = admin_user.role
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.','danger')

    return render_template('admin_login.html')


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


with app.app_context():
    db.create_all()
    admin=User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
    username='admin',
    email='admin@gmail.com',
    role='admin',
    password=generate_password_hash('admin'),
    is_admin=True,
    profile_pic=None,
    category=None,
    platform=None,
    followers=0,
    rating=0,
    mobile=None,
    target=0,
    languages=None,
    content_style=None
    )

    db.session.add(admin)
    db.session.commit()


if __name__ == '__main__':
    app.run(debug=True)
    