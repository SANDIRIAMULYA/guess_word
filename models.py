from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)  # email
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="PLAYER")  # PLAYER, ADMIN, HEAD_ADMIN

    # --- Password helpers ---
    def set_password(self, password: str):
        self.password = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password, password)

    # --- Role helpers ---
    def is_admin(self) -> bool:
        """Return True if user is ADMIN or HEAD_ADMIN"""
        return self.role.upper() in ["ADMIN", "HEAD_ADMIN"]

    def is_head_admin(self) -> bool:
        return self.role.upper() == "HEAD_ADMIN"

    def is_player(self) -> bool:
        return self.role.upper() == "PLAYER"


class Word(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    word = db.Column(db.String(5), unique=True, nullable=False)


class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    chosen_word = db.Column(db.String(5))
    date = db.Column(db.Date)
    status = db.Column(db.String(10))  # WIN, LOSS, None
    attempts = db.Column(db.Integer, default=0)


class Guess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey("game.id"), nullable=False)
    guess_word = db.Column(db.String(5), nullable=False)
    attempt_number = db.Column(db.Integer, nullable=False)
    result = db.Column(db.String(5), nullable=False)  # e.g. "GOGXY"
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class PendingAdminRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)  # hashed
    status = db.Column(db.String(20), default="PENDING")  # PENDING, APPROVED, REJECTED
