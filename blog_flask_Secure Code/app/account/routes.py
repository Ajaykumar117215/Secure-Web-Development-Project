from flask import Blueprint, render_template, request, redirect, flash, url_for, current_app, abort
from app.extensions import db, login_manager, limiter
from app.models.user import Blog_User
from app.models.posts import Blog_Posts
from app.account.forms import The_Accounts
from app.models.stats import Blog_Stats
from app.models.bookmarks import Blog_Bookmarks
from app.models.likes import Blog_Likes
from app.models.comments import Blog_Comments, Blog_Replies
from app.account.helpers import hash_pw
from app.models.helpers import  update_stats_users_total, update_stats_users_active, delete_comment, delete_reply, change_authorship_of_all_post, update_bookmarks, update_likes
from app.general_helpers.helpers import check_image_filename
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import check_password_hash  # used in login
from werkzeug.utils import secure_filename
from sqlalchemy import desc
from datetime import datetime
import uuid as uuid
import os

account = Blueprint('account', __name__)

# Pages: login, logout, signup, account
# Routes available for all registered users (all user types) + login and signup (available for all registered and non-registered users)

# ***********************************************************************************************
# LOGIN, SIGN UP, LOG OUT
@login_manager.user_loader
def load_user(user_id):
    return Blog_User.query.get(int(user_id))

@account.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        username = request.form.get("username", "").strip()

        # V-09 FIX: Basic server-side email format check (form validator covers the form path)
        import re
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Please enter a valid email address.")
            return redirect(url_for("account.signup"))

        # V-05 FIX: Enforce password complexity requirements.
        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return redirect(url_for("account.signup"))
        if not any(c.isupper() for c in password):
            flash("Password must contain at least one uppercase letter.")
            return redirect(url_for("account.signup"))
        if not any(c.isdigit() for c in password):
            flash("Password must contain at least one digit.")
            return redirect(url_for("account.signup"))

        if Blog_User.query.filter_by(email=email).first():
            flash("This email is already registered with us. Log-in instead!")
            return redirect(url_for("account.login"))

        new_user = Blog_User(
            name=username,
            email=email,
            password=hash_pw(password),
            type="user"
        )
        db.session.add(new_user)
        db.session.commit()
        update_stats_users_total()
        update_stats_users_active(1)

        login_user(new_user)

        return redirect(url_for('account.dashboard'))

    return render_template('account/signup.html', logged_in=current_user.is_authenticated)

# V-04 FIX: Rate-limit login to 5 attempts per minute per IP to prevent brute force.
@account.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        the_user = Blog_User.query.filter_by(email=email).first()
        # V-04 FIX: Use a single generic message to prevent email enumeration.
        if not the_user or not check_password_hash(the_user.password, password):
            flash("Invalid credentials, please try again.")
            return redirect(url_for("account.login"))
        # user is blocked:
        elif the_user.blocked == "TRUE":
            flash("Your account has been blocked. Please contact us for more information.")
            return redirect(url_for("account.login"))
        # credentials valid and account active:
        else:
            login_user(the_user)
            return redirect(url_for('account.dashboard'))
    return render_template("account/login.html", logged_in=current_user.is_authenticated)


@account.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('website.home'))

# ***********************************************************************************************
# DASHBOARDs
# displaying user dashboard after log-in according to the account type: user, author, or admin
@account.route("/dashboard")
@login_required
def dashboard():
    if current_user.type == "user":
        latest_posts = db.session.query(Blog_Posts).filter(
            Blog_Posts.admin_approved == "TRUE", Blog_Posts.date_to_post <= datetime.utcnow()).order_by(desc(Blog_Posts.date_to_post)).limit(3)
        latest_bookmarks = Blog_Bookmarks.query.filter_by(user_id=current_user.id).limit(9)
        if latest_bookmarks.count() == 0:
            latest_bookmarks = None
        return render_template('account/dashboard_user.html', name=current_user.name, logged_in=True, latest_posts=latest_posts, latest_bookmarks=latest_bookmarks)
    elif current_user.type == "author":
        posts_pending_admin = Blog_Posts.query.filter(Blog_Posts.admin_approved == "FALSE").filter(
            Blog_Posts.author_id == current_user.id).all()
        return render_template('account/dashboard_author_dash.html', name=current_user.name, logged_in=True, posts_pending_admin=posts_pending_admin)
    else:
        current_stats = Blog_Stats.query.get_or_404(1)
        posts_pending_approval = Blog_Posts.query.filter_by(
            admin_approved="FALSE").all()
        return render_template('account/dashboard_admin_dash.html', name=current_user.name, logged_in=True, posts_pending_approval=posts_pending_approval, current_stats=current_stats)

# ***********************************************************************************************
# OWN ACCOUNT MANAGEMENT, BOOKMARKS, HISTORY

# Managing own account information - available to all users
@account.route("/dashboard/manage_account")
@login_required
def manage_acct():
    return render_template("account/account_mgmt.html", logged_in=current_user.is_authenticated)

# Update own account information
@account.route("/dashboard/manage_account/update/<int:id>", methods=["GET", "POST"])
@login_required
def update_own_acct_info(id):
    # V-02 FIX: Reject requests where the URL id does not match the logged-in user.
    if id != current_user.id:
        abort(403)
    form = The_Accounts()
    user_at_hand = Blog_User.query.get_or_404(id)

    if form.validate_on_submit():
        user_at_hand.name = form.username.data
        user_at_hand.email = form.email.data
        user_at_hand.about = form.about.data

        try:
            db.session.commit()
            flash("Account information updated successfully!")
            return redirect(url_for('account.manage_acct'))
        except:
            flash("Oops, error updating account information, try again.")
            return redirect(url_for('account.manage_acct'))

    # filling out the form with saved post data
    form.username.data = user_at_hand.name
    form.email.data = user_at_hand.email
    form.about.data = user_at_hand.about
    return render_template("account/account_mgmt_update.html", logged_in=current_user.is_authenticated, form=form)

# Update account information: changing the picture
@account.route("/dashboard/manage_account/update_picture/<int:id>", methods=["GET", "POST"])
@login_required
def update_own_acct_picture(id):
    # V-02 FIX: Ownership check — only the account owner may update their picture.
    if id != current_user.id:
        abort(403)
    form = The_Accounts()
    user_at_hand = Blog_User.query.get_or_404(id)
    if user_at_hand.picture == "" or user_at_hand.picture == "Picture_default.jpg":
        profile_picture = None
    else:
        profile_picture = user_at_hand.picture

    if request.method == "POST":
        if form.picture.data:
            # get name from image file:
            pic_filename = secure_filename(form.picture.data.filename)

            # check if extension is allowed:
            if not check_image_filename(pic_filename):
                flash("Sorry, this image extension is not allowed.")
                return redirect(url_for('account.update_own_acct_picture', id=id))

            # insert a unique id to the filename to make sure there arent two pictures with the same name:
            pic_filename_unique = str(uuid.uuid1()) + "_" + pic_filename
            user_at_hand.picture = pic_filename_unique

            # get the new image
            the_img_file = request.files['picture']
        try:
            # save the img to folder and path to user
            the_img_file.save(os.path.join(
                current_app.config["PROFILE_IMG_FOLDER"], pic_filename_unique))
            # delete the old picture from folder
            if profile_picture != None and os.path.exists(os.path.join(current_app.config["PROFILE_IMG_FOLDER"], profile_picture)):
                os.remove(os.path.join(
                    current_app.config["PROFILE_IMG_FOLDER"], profile_picture))

            db.session.commit()
            flash("Picture updated successfully!")
            return redirect(url_for('account.manage_acct'))
        except:
            flash("Oops, error updating profile picture, try again.")
            return redirect(url_for('account.manage_acct'))

    return render_template("account/account_mgmt_picture.html", logged_in=current_user.is_authenticated, form=form, profile_picture=profile_picture)


# Delete account
# When an account is deleted, this changes the number of active users in the stats
# When this user is deleted, their picture, bookmarks, and likes are deleted as well.
# If this user is an author, the authorship of the post will be transfered to the blog team.
@account.route("/dashboard/manage_account/delete/<int:id>", methods=["GET", "POST"])
@login_required
def delete_own_acct(id):
    # V-02 FIX: Ownership check — only the account owner may delete their account.
    if id != current_user.id:
        abort(403)
    user_at_hand = Blog_User.query.get_or_404(id)
    if request.method == "POST":
        # impede the deletion of super_admin
        if id == 1:
            flash("Authorization denied: this user cannot be deleted")
            return redirect(url_for('account.manage_acct'))
        else:
            try:
                # if user is author, transfer the authorship of the posts to the default author
                if user_at_hand.type == "author":
                    change_authorship_of_all_post(user_at_hand.id, 2)

                # if user has comments/replies, change ownership (to default user of id 3 and delete or mark as blocked ([deleted]).
                if user_at_hand.comments:
                    comments = Blog_Comments.query.filter_by(
                        user_id=user_at_hand.id).all()
                    for comment in comments:
                        comment.user_id = 3
                        delete_comment(comment.id)

                if user_at_hand.replies:
                    replies = comments = Blog_Replies.query.filter_by(
                        user_id=user_at_hand.id).all()
                    for reply in replies:
                        reply.user_id = 3
                        delete_reply(reply.id)
                
                # delete bookmarks and likes
                if user_at_hand.likes:
                    likes = Blog_Likes.query.filter_by(
                        user_id=user_at_hand.id).all()
                    for like in likes:
                        db.session.delete(like)
                        update_likes(-1)

                if user_at_hand.bookmarks:
                    bookmarks = Blog_Bookmarks.query.filter_by(
                        user_id=user_at_hand.id).all()
                    for bookmark in bookmarks:
                        db.session.delete(bookmark)
                        update_bookmarks(-1)

                # delete user's picture
                if user_at_hand.picture == "" or user_at_hand.picture == "Picture_default.jpg":
                    profile_picture = None
                else:
                    profile_picture = user_at_hand.picture

                if profile_picture != None and os.path.exists(os.path.join(current_app.config["PROFILE_IMG_FOLDER"], profile_picture)):
                    os.remove(os.path.join(
                        current_app.config["PROFILE_IMG_FOLDER"], profile_picture))
                    
                # delete user
                db.session.delete(user_at_hand)
                db.session.commit()
                flash("Your account was deleted successfully.")
                update_stats_users_active(-1)
                return redirect(url_for("website.home"))
            except:
                flash("There was a problem deleting your account.")
                db.session.rollback()
                return redirect(url_for('account.manage_acct'))
    else:
        return render_template("account/account_mgmt_delete.html", logged_in=current_user.is_authenticated)

# INBOX
# User can see their comments and replies the comment received.
@account.route("/dashboard/inbox", methods=["GET", "POST"])
@login_required
def inbox():
    users_comments = db.session.query(Blog_Comments).filter(
        Blog_Comments.user_id == current_user.id).order_by(desc(Blog_Comments.date_submitted)).limit(25)

    replies = Blog_Replies.query.filter(
        Blog_Replies.comment_id.in_([c.id for c in users_comments])).all()
    
    if users_comments.count() == 0:
        users_comments = None

    return render_template("account/inbox.html", logged_in=current_user.is_authenticated, users_comments=users_comments, replies=replies)

