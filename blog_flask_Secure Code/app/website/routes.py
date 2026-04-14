import logging
from flask import Blueprint, render_template, request, jsonify, make_response
from app.extensions import db, csrf, limiter
from app.website.contact import send_email
from app.models.contact import Blog_Contact
from app.models.themes import Blog_Theme
from app.models.posts import Blog_Posts
from app.models.user import Blog_User
from app.models.likes import Blog_Likes
from app.models.bookmarks import Blog_Bookmarks
from app.models.comments import Blog_Comments, Blog_Replies
from app.models.helpers import update_likes, update_bookmarks, delete_comment, delete_reply
from flask_login import current_user, login_required
from flask_wtf.csrf import validate_csrf
from wtforms import ValidationError
from datetime import datetime
from sqlalchemy import desc

logger = logging.getLogger(__name__)

website = Blueprint('website', __name__,
                    static_folder="../static", template_folder="../template")


# Blog website pages: Home Page, All posts, About, Contact page
# Routes available for registered and non-registered users alike

@website.route("/")
def home():
    # query database for themes while getting picture src
    posts_themes = [(u.theme, u.picture, u.id)
                    for u in db.session.query(Blog_Theme).all()]
    theme_list = [t[2] for t in posts_themes]

    # query posts to get the latest 3 posts of each theme.
    posts_all = []
    forth_theme_post_ids = []
    for num_themes in theme_list:
        query = db.session.query(Blog_Posts).filter(
                Blog_Posts.admin_approved == "TRUE", Blog_Posts.date_to_post <= datetime.utcnow(),
            Blog_Posts.theme_id == num_themes).order_by(desc(Blog_Posts.date_to_post)).limit(3)
        posts_all.append(query.all())
        if num_themes == 4:
            for this_query in query:
                forth_theme_post_ids.append(this_query.id)
    posts_all = posts_all[0] + posts_all[1] + posts_all[2] + posts_all[3]

    return render_template('website/index.html', posts_all=posts_all, posts_themes=posts_themes, logged_in=current_user.is_authenticated, forth_theme_post_ids=forth_theme_post_ids)

# route to 'All Posts' page or page by chosen theme
@website.route("/all/<int:index>")
def all(index):
    index = int(index)
    all_blog_posts = None
    chosen_theme = ""
    intros = []
    if index != 0:
        chosen_theme = db.session.query(
            Blog_Theme).filter(Blog_Theme.id == index).first().theme
        all_blog_posts = db.session.query(Blog_Posts).filter(Blog_Posts.theme_id == index,
            Blog_Posts.admin_approved == "TRUE", Blog_Posts.date_to_post <= datetime.utcnow(),
        ).order_by(desc(Blog_Posts.date_to_post)).limit(25)
    else:
        all_blog_posts = db.session.query(Blog_Posts).filter(
            Blog_Posts.admin_approved == "TRUE", Blog_Posts.date_to_post <= datetime.utcnow(),
            ).order_by(desc(Blog_Posts.date_to_post)).limit(25)
    for post in all_blog_posts:
        if len(post.intro) > 300:
            cut_intro_if_too_long = f"{post.intro[:300]}..."
            intros.append(cut_intro_if_too_long)
        else:
            intros.append(post.intro)

    return render_template('website/all_posts.html', all_blog_posts=all_blog_posts, chosen_theme=chosen_theme, intros=intros, logged_in=current_user.is_authenticated)

@website.route("/about/")
def about():
    authors_all = db.session.query(Blog_User).filter(
        Blog_User.blocked == "FALSE", Blog_User.type == "author",
        ).order_by(desc(Blog_User.id)).limit(25)
    return render_template('website/about.html', authors_all=authors_all, logged_in=current_user.is_authenticated)

# V-13 FIX: Rate-limit contact form to 5 POST requests per 10 minutes per IP.
@website.route("/contact/", methods=['POST', 'GET'])
@limiter.limit("5 per 10 minutes", methods=["POST"])
def contact():
    if request.method == "POST":
        contact_name = request.form['contact_name']
        contact_email = request.form['contact_email']
        contact_message = request.form['contact_message']
        new_contact = Blog_Contact(
            name=contact_name, email=contact_email, message=contact_message)
        try:
            # push to database:
            db.session.add(new_contact)
            db.session.commit()
            # send email:
            send_email(contact_name, contact_email, contact_message)
            return render_template('website/contact.html', msg_sent=True, logged_in=current_user.is_authenticated)
        except Exception as e:
            # V-14 FIX: Log the exception server-side; return only a generic message to the client.
            # Original vulnerable code exposed str(e) directly in the HTTP response (CWE-209).
            logger.error("Contact form DB/email error: %s", e, exc_info=True)
            db.session.rollback()
            return render_template('website/contact.html', msg_sent=False, error=True, logged_in=current_user.is_authenticated)
    return render_template('website/contact.html', msg_sent=False, logged_in=current_user.is_authenticated)


@website.route("/post/<int:index>", methods=["GET", "POST"])
def blog_post(index):
    # get the post
    blog_post = db.session.query(Blog_Posts).filter(Blog_Posts.id == index,
                                                    Blog_Posts.admin_approved == "TRUE", Blog_Posts.date_to_post <= datetime.utcnow(),
                                                    ).order_by(Blog_Posts.date_submitted.desc()).first()
    # get the likes
    post_likes = db.session.query(Blog_Likes).filter(
        Blog_Likes.post_id == index).all()

    # check if user is logged in, and if so, already liked or bookmarked this post
    user_liked = False
    user_bookmarked = False
    if current_user.is_authenticated:
        like = db.session.query(Blog_Likes).filter(
            Blog_Likes.user_id == current_user.id, Blog_Likes.post_id == index).first()
        bookmark = db.session.query(Blog_Bookmarks).filter(
            Blog_Bookmarks.user_id == current_user.id, Blog_Bookmarks.post_id == index).first()
    else:
        like = False
        bookmark = False
    if like:
        user_liked = True
    if bookmark:
        user_bookmarked = True
    # get the comments
    comments = db.session.query(Blog_Comments).filter(
        Blog_Comments.post_id == index).order_by(Blog_Comments.date_submitted.desc()).limit(25)
    # get the replies
    replies = db.session.query(Blog_Replies).filter(Blog_Replies.post_id == index,
                                                    ).order_by(Blog_Replies.date_submitted.asc()).limit(100)
    return render_template('website/post.html', blog_posts=blog_post, logged_in=current_user.is_authenticated, comments=comments, replies=replies, post_likes=post_likes, user_liked=user_liked, user_bookmarked=user_bookmarked)


# V-07 FIX: Exempt from global CSRF but validate X-CSRFToken header manually.
# V-08 FIX (partial): login_required added; ownership check is enforced server-side.
@website.route("/comment_post/<int:index>", methods=["POST"])
@csrf.exempt
@login_required
def post_comment(index):
    # V-07 FIX: Validate CSRF token sent in X-CSRFToken request header.
    try:
        validate_csrf(request.headers.get('X-CSRFToken'))
    except ValidationError:
        return make_response(jsonify({"message": "CSRF token missing or invalid"}), 403)

    data = request.get_json()
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        data = request.get_json()
        if not data.get('comment') and not data.get('reply'):
            return make_response(jsonify({"message": "Comment empty"}), 400)
        if data.get('reply') and not data.get('comment'):
            # add reply
            reply = Blog_Replies(
                text=data.get('reply'), post_id=index, user_id=current_user.id, comment_id=int(data.get('commentId')))
            db.session.add(reply)
            db.session.commit()
            return make_response(jsonify({"message": "Reply added"}), 200)
        elif data.get('comment') and not data.get('reply'):
            # add comment
            comment = Blog_Comments(
                text=data.get('comment'), post_id=index, user_id=current_user.id)
            db.session.add(comment)
            db.session.commit()
            return make_response(jsonify({"message": "Comment added"}), 200)
        else:
            return make_response(jsonify({"message": "Must be either a comment or a reply"}), 400)
    else:
        return make_response(jsonify({"message": "Content type not supported"}), 412)


# V-07 FIX: Exempt from global CSRF, manual header validation below.
# V-08 FIX: Requires authentication and verifies ownership before deletion.
@website.route("/delete_comment_or_reply/<int:index>", methods=["POST"])
@csrf.exempt
@login_required
def post_delete_comment(index):
    # V-07 FIX: Validate CSRF token sent in X-CSRFToken request header.
    try:
        validate_csrf(request.headers.get('X-CSRFToken'))
    except ValidationError:
        return make_response(jsonify({"message": "CSRF token missing or invalid"}), 403)

    data = request.get_json()
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        data = request.get_json()
        if not data.get('commentId') and not data.get('replyId'):
            return make_response(jsonify({"message": "Nothing to delete"}), 400)

        if data.get('replyId') and not data.get('commentId'):
            # V-08 FIX: Verify ownership — only the reply author or an admin may delete.
            reply = Blog_Replies.query.get(int(data.get('replyId')))
            if not reply:
                return make_response(jsonify({"message": "Reply not found"}), 404)
            if current_user.type not in ("admin", "super_admin") and reply.user_id != current_user.id:
                return make_response(jsonify({"message": "Unauthorized"}), 403)
            res = delete_reply(int(data.get('replyId')))
            if res == "success":
                return make_response(jsonify({"message": "Successfully deleted"}), 200)
            else:
                return make_response(jsonify({"message": "Reply not found"}), 404)

        elif data.get('commentId') and not data.get('replyId'):
            # V-08 FIX: Verify ownership — only the comment author or an admin may delete.
            comment = Blog_Comments.query.get(int(data.get('commentId')))
            if not comment:
                return make_response(jsonify({"message": "Comment not found"}), 404)
            if current_user.type not in ("admin", "super_admin") and comment.user_id != current_user.id:
                return make_response(jsonify({"message": "Unauthorized"}), 403)
            res = delete_comment(int(data.get('commentId')))
            if res == "success":
                return make_response(jsonify({"message": "Successfully deleted"}), 200)
            else:
                return make_response(jsonify({"message": "Comment not found"}), 404)
        else:
            return make_response(jsonify({"message": "Must be either a commentId or a replyId"}), 400)
    else:
        return make_response(jsonify({"message": "Content type not supported"}), 412)


# V-07 FIX: Exempt from global CSRF, manual header validation below.
@website.route("/like_post/<int:index>", methods=["POST"])
@csrf.exempt
@login_required
def post_like(index):
    # V-07 FIX: Validate CSRF token sent in X-CSRFToken request header.
    try:
        validate_csrf(request.headers.get('X-CSRFToken'))
    except ValidationError:
        return make_response(jsonify({"message": "CSRF token missing or invalid"}), 403)

    # check if post exists
    post = db.session.query(Blog_Posts).filter_by(id=index)
    if not post:
        return jsonify({"error": "post does not exist"}, 400)
    # check how many likes this post has
    post_likes = db.session.query(Blog_Likes).filter(
        Blog_Likes.post_id == index).all()

    # check if user already liked this post
    like = db.session.query(Blog_Likes).filter(
        Blog_Likes.user_id == current_user.id, Blog_Likes.post_id == index).first()
    if like:
        db.session.delete(like)
        db.session.commit()
        update_likes(-1)
        has_liked = "false"
    else:
        like = Blog_Likes(user_id=current_user.id, post_id=index)
        db.session.add(like)
        db.session.commit()
        update_likes(1)
        has_liked = "true"
    return jsonify({"likes": len(post_likes), "user_liked": has_liked})


# V-07 FIX: Exempt from global CSRF, manual header validation below.
@website.route("/bookmark_post/<int:index>", methods=["POST"])
@csrf.exempt
@login_required
def post_bookmark(index):
    # V-07 FIX: Validate CSRF token sent in X-CSRFToken request header.
    try:
        validate_csrf(request.headers.get('X-CSRFToken'))
    except ValidationError:
        return make_response(jsonify({"message": "CSRF token missing or invalid"}), 403)

    # check if post exists
    post = db.session.query(Blog_Posts).filter_by(id=index)
    if not post:
        return jsonify({"error": "post does not exist"}, 400)

    # check if user already bookmarked this post to decide whether to add or remove the bookmark
    bookmark = db.session.query(Blog_Bookmarks).filter(
        Blog_Bookmarks.user_id == current_user.id, Blog_Bookmarks.post_id == index).first()
    if bookmark:
        db.session.delete(bookmark)
        db.session.commit()
        update_bookmarks(-1)
        has_bookmarked = "false"
    else:
        bookmark = Blog_Bookmarks(user_id=current_user.id, post_id=index)
        db.session.add(bookmark)
        db.session.commit()
        update_bookmarks(1)
        has_bookmarked = "true"
    return jsonify({"user_bookmarked": has_bookmarked})
