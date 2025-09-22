import os
import random
import re
from datetime import date, datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from models import db, User, Word, Game, Guess, PendingAdminRequest
from game_logic import get_feedback

# ensure data folder exists
os.makedirs(os.path.join(os.path.abspath(os.path.dirname(__file__)), "data"), exist_ok=True)

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# Configure your Head admin email & password here (change to secure values)
HEAD_EMAIL = "amulyasandiri123@gmail.com"
HEAD_PASSWORD = "Pass@1234"  # change in production or read from env/config


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

# ----------------- Validation helpers -----------------
def valid_email(e: str) -> bool:
    """Simple email validation"""
    if not e:
        return False
    # basic regex for email
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e) is not None

def valid_password(p: str) -> bool:
    """
    Password must be at least 5 chars, contain letter, digit, one of $ % * @,
    and NOT contain spaces.
    """
    if not p or len(p) < 5:
        return False
    if " " in p:
        return False
    return bool(re.search(r"[A-Za-z]", p)) and bool(re.search(r"\d", p)) and bool(re.search(r"[$%*@]", p))

# initial 20 words (uppercase)
INITIAL_WORDS = [
    "APPLE","BRAIN","CHAIR","TABLE","PLANT","HOUSE","LIGHT","WORLD","SMILE","GRASS",
    "FRAME","MOUSE","PHONE","TRAIN","CLOUD","RIVER","DRIVE","STONE","NIGHT","CANDY"
]

def setup_db():
    with app.app_context():
        db.create_all()

        # seed words
        if Word.query.count() == 0:
            for w in INITIAL_WORDS:
                db.session.add(Word(word=w.upper()))
            db.session.commit()

        # seed head admin if not exists (use HEAD_ADMIN role)
        if User.query.filter_by(role="HEAD_ADMIN").count() == 0:
            head_admin = User(
                username=HEAD_EMAIL.strip().lower(),
                password=generate_password_hash(HEAD_PASSWORD),
                role="HEAD_ADMIN"
            )
            db.session.add(head_admin)
            db.session.commit()





@app.context_processor
def inject_now():
    return {"current_year": datetime.utcnow().year}

# ---- Routes ----
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard" if current_user.is_admin() else "player_dashboard"))
    return render_template("welcome.html")

# Registration (Players only)
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard" if current_user.is_admin() else "player_dashboard"))

    if request.method == "POST":
        email = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        # validations
        if not valid_email(email):
            flash("Enter a valid email address.", "danger")
            return render_template("register.html")
        if not valid_password(password):
            flash("Password must be at least 5 chars, contain letters, numbers and one of $ % * @, and contain no spaces.", "danger")
            return render_template("register.html")

        # Prevent registering as ADMIN via this form
        if User.query.filter_by(username=email).first():
            flash("Email already registered.", "danger")
            return render_template("register.html")

        user = User(username=email, password=generate_password_hash(password), role="PLAYER")
        db.session.add(user)
        db.session.commit()
        flash("Registered successfully. Please log in.", "success")
        return redirect(url_for("player_login"))

    return render_template("register.html")

# Login
@app.route("/login/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        # require user exists, correct password, and is admin (covers HEAD_ADMIN too)
        if not user or not check_password_hash(user.password, password) or not user.is_admin():
            flash("Invalid admin username or password.", "danger")
            return render_template("admin_login.html")

        login_user(user)
        flash(f"Welcome Admin {user.username}!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_login.html")




# --- Player Login ---
@app.route("/login/player", methods=["GET", "POST"])
def player_login():
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard" if current_user.is_admin() else "player_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username, role="PLAYER").first()
        if not user or not check_password_hash(user.password, password):
            flash("Invalid Player credentials.", "danger")
            return render_template("player_login.html")

        login_user(user)
        flash(f"Welcome, {user.username}!", "success")
        return redirect(url_for("player_dashboard"))

    return render_template("player_login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("home"))  

@app.route("/player")
@login_required
def player_dashboard():
    if current_user.is_admin():
        return redirect(url_for("admin_dashboard"))

    today = date.today()
    games_today = Game.query.filter_by(user_id=current_user.id, date=today).count()
    recent_games = Game.query.filter_by(user_id=current_user.id).order_by(Game.date.desc()).limit(5).all()
    return render_template("player_dashboard.html", games_today=games_today, recent_games=recent_games)

# Start a new game (pick random word)
@app.route("/start_game", methods=["POST", "GET"])
@login_required
def start_game():
    if current_user.is_admin():
        return redirect(url_for("admin_dashboard"))

    today = date.today()
    games_count = Game.query.filter_by(user_id=current_user.id, date=today).count()
    if games_count >= 3:
        flash("You can only start 3 games per day.", "warning")
        return redirect(url_for("player_dashboard"))

    # pick random word from DB
    words = Word.query.all()
    if not words:
        flash("No words available (admin needs to add).", "danger")
        return redirect(url_for("player_dashboard"))
    chosen = random.choice(words).word.upper()
    new_game = Game(user_id=current_user.id, chosen_word=chosen, date=today, status=None, attempts=0)
    db.session.add(new_game)
    db.session.commit()
    return redirect(url_for("view_game", game_id=new_game.id))

# View / play a game
@app.route("/game/<int:game_id>", methods=["GET", "POST"])
@login_required
def view_game(game_id):
    game = Game.query.get_or_404(game_id)

    # ensure player access or admin access
    if game.user_id != current_user.id and not current_user.is_admin():
        flash("Not authorized to view that game.", "danger")
        return redirect(url_for("player_dashboard"))

    if request.method == "POST" and game.status is None:
        guess_raw = request.form.get("guess", "").strip().upper()
        # Validate guess: 5 letters, uppercase alphabetic
        if len(guess_raw) != 5 or not guess_raw.isalpha():
            flash("Enter a valid 5-letter word (letters only).", "danger")
            return redirect(url_for("view_game", game_id=game.id))

        # Ensure user has not exceeded 5 attempts on this game
        if game.attempts >= 5:
            flash("No more attempts left for this game.", "warning")
            return redirect(url_for("view_game", game_id=game.id))

        # Compute feedback
        feedback = get_feedback(game.chosen_word, guess_raw)

        # increment attempts and save guess
        game.attempts += 1
        guess = Guess(game_id=game.id, guess_word=guess_raw, attempt_number=game.attempts, result=feedback)

        db.session.add(guess)

        if feedback == "GGGGG":
            game.status = "WIN"
            flash("🎉 Congratulations — you guessed the word!", "success")
        elif game.attempts >= 5:
            game.status = "LOSS"
            flash(f"❌ Better luck next time. The word was {game.chosen_word}.", "info")

        db.session.add(game)
        db.session.commit()
        return redirect(url_for("view_game", game_id=game.id))

    # Prepare display data: earlier guesses
    guesses = Guess.query.filter_by(game_id=game.id).order_by(Guess.attempt_number).all()
    display = []
    for g in guesses:
        colors = []
        for ch in g.result:
            if ch == "G":
                colors.append("green")
            elif ch == "O":
                colors.append("orange")
            else:
                colors.append("grey")
        display.append({"word": g.guess_word, "colors": colors, "attempt": g.attempt_number})

    # In app.py
    for row in display:
        row['zipped'] = list(zip(row['word'], row['colors']))  # Use dictionary keys
    return render_template("game.html", game=game, display=display)


# Admin dashboard
@app.route("/admin")
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        flash("Admin access required.", "danger")
        return redirect(url_for("player_dashboard"))

    words = Word.query.order_by(Word.word).all()

    requests = []
    if current_user.is_head_admin():
        requests = PendingAdminRequest.query.filter_by(status="PENDING").all()

    return render_template("admin_dashboard.html", words=words, requests=requests)


@app.route("/admin/add_word", methods=["POST"])
@login_required
def admin_add_word():
    if not current_user.is_admin():
        return redirect(url_for("player_dashboard"))
    w = request.form.get("word", "").strip().upper()
    if len(w) != 5 or not w.isalpha():
        flash("Word must be 5 alphabetic letters.", "danger")
    elif Word.query.filter_by(word=w).first():
        flash("Word already exists.", "warning")
    else:
        db.session.add(Word(word=w))
        db.session.commit()
        flash("Word added.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/remove_word/<int:word_id>", methods=["POST"])
@login_required
def admin_remove_word(word_id):
    if not current_user.is_admin():
        return redirect(url_for("player_dashboard"))
    w = Word.query.get(word_id)
    if w:
        db.session.delete(w)
        db.session.commit()
        flash("Word removed.", "info")
    return redirect(url_for("admin_dashboard"))

# -------- Admin-request (submit) --------
@app.route("/request-admin", methods=["GET", "POST"])
def request_admin():
    # If already a user, redirect to login
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard" if current_user.is_admin() else "player_dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")

        # validations
        if not valid_email(email):
            flash("Enter a valid email address.", "danger")
            return render_template("request_admin.html")
        if not full_name:
            flash("Enter your full name.", "danger")
            return render_template("request_admin.html")
        if not valid_password(password):
            flash("Password must be at least 5 chars, contain letters, numbers and one of $ % * @, and contain no spaces.", "danger")
            return render_template("request_admin.html")

        # Prevent duplicate registrations
        if User.query.filter_by(username=email).first():
            flash("This email is already registered. Please log in.", "danger")
            return redirect(url_for("admin_login"))

        # Prevent duplicate pending request
        if PendingAdminRequest.query.filter_by(email=email).first():
            flash("A request for this email is already pending.", "info")
            return redirect(url_for("admin_login"))

        # Save the request (store hashed password)
        req = PendingAdminRequest(
            email=email,
            full_name=full_name,
            password=generate_password_hash(password),
            status="PENDING"
        )
        db.session.add(req)
        db.session.commit()

        flash("Request submitted. Head admin will review and approve/reject.", "success")
        return redirect(url_for("admin_login"))

    return render_template("request_admin.html")

# -------- Head views pending requests --------
@app.route("/admin-requests")
@login_required
def admin_requests():
    if current_user.role != "HEAD":
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard") if hasattr(current_user, "is_admin") else url_for("player_dashboard"))

    requests = PendingAdminRequest.query.filter_by(status="PENDING").all()
    return render_template("admin_requests.html", requests=requests)

@app.route("/approve-request/<int:req_id>", methods=["POST"])
@login_required
def approve_request(req_id):
    if not current_user.is_head_admin():
        flash("Access denied!", "danger")
        return redirect(url_for("player_dashboard"))

    req = PendingAdminRequest.query.get_or_404(req_id)
    if req.status != "PENDING":
        flash("Request already processed.", "info")
        return redirect(url_for("admin_dashboard"))

    # create Admin user using hashed password from request
    existing = User.query.filter_by(username=req.email).first()
    if existing:
        existing.role = "ADMIN"
    else:
        new_admin = User(username=req.email, password=req.password, role="ADMIN")
        db.session.add(new_admin)

    req.status = "APPROVED"
    db.session.commit()

    flash(f"Admin {req.email} approved!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/reject-request/<int:req_id>", methods=["POST"])
@login_required
def reject_request(req_id):
    if not current_user.is_head_admin():
        flash("Access denied!", "danger")
        return redirect(url_for("player_dashboard"))

    req = PendingAdminRequest.query.get_or_404(req_id)
    req.status = "REJECTED"
    db.session.commit()

    flash(f"Admin request from {req.email} rejected!", "info")
    return redirect(url_for("admin_dashboard"))


# Reports route adapted (kept your logic)
@app.route("/admin/reports")
@login_required
def admin_reports():
    if not current_user.is_admin():
        return redirect(url_for("player_dashboard"))

    # Optional query params
    q_date = request.args.get("date")  # expected YYYY-MM-DD
    q_username = request.args.get("username")

    # If user report requested:
    user_report = None
    if q_username:
        u = User.query.filter_by(username=q_username).first()
        if not u:
            flash("User not found for report.", "warning")
        else:
            from sqlalchemy import func
            rows = db.session.query(Game.date,
                                    func.count(Game.id).label("games"),
                                    func.sum((Game.status == "WIN").cast(db.Integer)).label("wins"))\
                    .filter(Game.user_id == u.id)\
                    .group_by(Game.date).order_by(Game.date.desc()).all()
            user_report = {"user": u, "rows": rows}

    # If daily report requested:
    daily_report = None
    if q_date:
        try:
            d = date.fromisoformat(q_date)
        except Exception:
            flash("Invalid date format. Use YYYY-MM-DD.", "danger")
            d = None
        if d:
            from sqlalchemy import func, distinct
            users_played = db.session.query(func.count(distinct(Game.user_id))).filter(Game.date == d).scalar()
            wins = db.session.query(func.count(Game.id)).filter(Game.date == d, Game.status == "WIN").scalar()
            daily_report = {"date": d, "users_played": users_played or 0, "wins": wins or 0}

    from sqlalchemy import func
    games_per_day = db.session.query(Game.date, func.count(Game.id)).group_by(Game.date).order_by(Game.date.desc()).limit(20).all()
    wins_losses = db.session.query(Game.status, func.count(Game.id)).group_by(Game.status).all()

    most_guessed = db.session.query(Guess.guess_word, func.count(Guess.id).label("count"))\
                    .group_by(Guess.guess_word).order_by(func.count(Guess.id).desc()).limit(20).all()

    return render_template("reports.html",
                           games_per_day=games_per_day,
                           wins_losses=wins_losses,
                           most_guessed=most_guessed,
                           daily_report=daily_report,
                           user_report=user_report)

# Compatibility route name used earlier
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.is_admin():
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("player_dashboard"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        setup_db()
    app.run(debug=True)
