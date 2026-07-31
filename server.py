import tornado.ioloop
import tornado.web
import tornado.websocket
import jwt
import os
import json
import random
import secrets
import string
import time
import asyncio
import sqlite3
import re
from urllib.parse import urlparse

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get('PORT', '5000'))
DB_PATH = os.environ.get('DB_PATH') or os.path.join(APP_ROOT, 'users.db')
CLERK_ISSUER = os.environ.get(
    'CLERK_ISSUER',
    'https://busy-skylark-3.clerk.accounts.dev',
).rstrip('/')
CLERK_JWKS_URL = os.environ.get(
    'CLERK_JWKS_URL',
    f'{CLERK_ISSUER}/.well-known/jwks.json',
)
AUTHORIZED_PARTIES = {
    value.strip().rstrip('/')
    for value in os.environ.get('CLERK_AUTHORIZED_PARTIES', '').split(',')
    if value.strip()
}
ALLOWED_ORIGINS = {
    value.strip().rstrip('/')
    for value in os.environ.get('ALLOWED_ORIGINS', '').split(',')
    if value.strip()
}
_jwks_client = jwt.PyJWKClient(CLERK_JWKS_URL, cache_keys=True)


def get_request_token(handler):
    auth_header = handler.request.headers.get('Authorization', '')
    if auth_header.lower().startswith('bearer '):
        return auth_header[7:].strip()
    return handler.get_cookie('__session', '') or ''


def parse_json_body(handler):
    try:
        data = json.loads(handler.request.body)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def verify_clerk_token(token, expected_parties=None):
    if not token:
        return None
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=['RS256'],
            issuer=CLERK_ISSUER,
            options={'verify_aud': False},
        )
        authorized_party = str(claims.get('azp', '')).rstrip('/')
        allowed_parties = AUTHORIZED_PARTIES or set(expected_parties or ())
        if allowed_parties and authorized_party not in allowed_parties:
            return None
        subject = claims.get('sub')
        return subject if isinstance(subject, str) and subject else None
    except Exception:
        return None


def verify_request_user(handler):
    forwarded_proto = handler.request.headers.get('X-Forwarded-Proto', '')
    forwarded_host = handler.request.headers.get('X-Forwarded-Host', '')
    protocol = forwarded_proto.split(',')[0].strip() or handler.request.protocol
    host = forwarded_host.split(',')[0].strip() or handler.request.host
    expected_party = f'{protocol}://{host}'.rstrip('/')
    return verify_clerk_token(get_request_token(handler), {expected_party})


def is_safe_display_name(value):
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 30
        and '<' not in value
        and '>' not in value
        and not any(ord(char) < 32 for char in value)
    )


def normalize_picture_url(value):
    if not value:
        return ''
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password:
        return None
    return value


class JsonHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json; charset=utf-8')
        self.set_header('Cache-Control', 'no-store')
        self.set_header('X-Content-Type-Options', 'nosniff')
        self.set_header('Referrer-Policy', 'same-origin')


class AuthenticatedJsonHandler(JsonHandler):
    def prepare(self):
        self.user_id = verify_request_user(self)
        if not self.user_id:
            self.set_status(401)
            self.finish(json.dumps({'error': 'Authentication required'}))


class PageHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header('X-Content-Type-Options', 'nosniff')
        self.set_header('Referrer-Policy', 'same-origin')
        self.set_header('X-Frame-Options', 'DENY')


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        clerk_id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
        display_name TEXT NOT NULL,
        profile_picture TEXT NOT NULL DEFAULT '',
        wins INTEGER NOT NULL DEFAULT 0,
        losses INTEGER NOT NULL DEFAULT 0,
        draws INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_id TEXT NOT NULL,
        to_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at INTEGER NOT NULL,
        UNIQUE(from_id, to_id)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS donate_taps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_id TEXT NOT NULL,
        to_id TEXT NOT NULL,
        room_code TEXT NOT NULL DEFAULT '',
        from_name TEXT NOT NULL DEFAULT '',
        from_pic TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        created_at INTEGER NOT NULL
    )''')
    # Migrate existing tables — ignore errors if columns already exist
    for col_sql in [
        'ALTER TABLE users ADD COLUMN profile_picture TEXT NOT NULL DEFAULT ""',
        'ALTER TABLE users ADD COLUMN wins INTEGER NOT NULL DEFAULT 0',
        'ALTER TABLE users ADD COLUMN losses INTEGER NOT NULL DEFAULT 0',
        'ALTER TABLE users ADD COLUMN draws INTEGER NOT NULL DEFAULT 0',
    ]:
        try:
            conn.execute(col_sql)
        except Exception:
            pass
    conn.commit()
    conn.close()


init_db()

rooms = {}
ws_tickets = {}


def make_code():
    return ''.join(random.choices(string.ascii_uppercase, k=4))


def check_winner(board):
    wins = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]]
    for combo in wins:
        a, b, c = combo
        if board[a] and board[a] == board[b] == board[c]:
            return board[a], combo
    return None, None


def safe_send(ws, msg):
    try:
        if ws and ws.ws_connection:
            ws.write_message(msg)
    except Exception:
        pass


def broadcast(room, msg):
    for player in room['players']:
        if player:
            safe_send(player, msg)


def get_profile(clerk_id):
    if not clerk_id:
        return None
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        'SELECT username, display_name, profile_picture, wins, losses, draws FROM users WHERE clerk_id = ?',
        (clerk_id,)
    ).fetchone()
    conn.close()
    if row:
        return {
            'id': clerk_id,
            'username': row[0], 'displayName': row[1], 'profilePicture': row[2],
            'wins': row[3], 'losses': row[4], 'draws': row[5],
        }
    return None


def record_game_result(winner_id, loser_id, is_draw, x_id, o_id):
    """Update wins/losses/draws for both players after a finished game."""
    conn = sqlite3.connect(DB_PATH)
    try:
        if is_draw:
            for pid in (x_id, o_id):
                if pid:
                    conn.execute('UPDATE users SET draws = draws + 1 WHERE clerk_id = ?', (pid,))
        else:
            if winner_id:
                conn.execute('UPDATE users SET wins = wins + 1 WHERE clerk_id = ?', (winner_id,))
            if loser_id:
                conn.execute('UPDATE users SET losses = losses + 1 WHERE clerk_id = ?', (loser_id,))
        conn.commit()
    finally:
        conn.close()


LANDING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1" />
  <title>Tic Tac Toe</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', sans-serif;
      background: #111;
      color: #fff;
      min-height: 100dvh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 32px 24px;
    }
    .wrap { width: 100%; max-width: 380px; display: flex; flex-direction: column; align-items: center; gap: 20px; }
    .logo { width: 68px; height: 68px; border-radius: 18px; }
    h1 { font-size: 2rem; font-weight: 700; letter-spacing: 0.18em; color: #22d3ee; text-transform: uppercase; text-align: center; }
    .sub { font-size: 0.88rem; color: #555; text-align: center; line-height: 1.5; }
    .btns { width: 100%; display: flex; flex-direction: column; gap: 10px; margin-top: 4px; }
    .btn { display: block; width: 100%; text-align: center; font-family: inherit; font-size: 0.95rem; font-weight: 600; padding: 14px 20px; border-radius: 12px; cursor: pointer; text-decoration: none; transition: opacity 0.15s, border-color 0.15s, color 0.15s; }
    .btn-primary { background: #22d3ee; color: #111; border: none; }
    .btn-primary:hover { opacity: 0.88; }
    .btn-secondary { background: transparent; color: #ccc; border: 1px solid #2a2a2a; }
    .btn-secondary:hover { border-color: #444; color: #fff; }
    .btn-ghost { background: transparent; color: #444; border: none; font-size: 0.85rem; font-weight: 500; padding: 10px 20px; }
    .btn-ghost:hover { color: #888; }
    .note { font-size: 0.75rem; color: #333; text-align: center; line-height: 1.6; }
  </style>
</head>
<body>
  <div class="wrap">
    <img class="logo" src="/logo.svg" alt="Tic Tac Toe" onerror="this.style.display='none'" />
    <h1>Tic Tac Toe</h1>
    <p class="sub">Local &amp; online multiplayer, AI opponents, voice chat</p>
    <div class="btns">
      <a class="btn btn-primary" href="/sign-in">Sign in with Google to Play</a>
      <a class="btn btn-secondary" href="/sign-up">Create Account</a>
      <a class="btn btn-ghost" href="/guest.html">Play as Guest</a>
    </div>
    <p class="note">A Google account is required to track your scores<br>and play online</p>
  </div>
  <div style="position:fixed;top:12px;right:16px;font-family:Inter,sans-serif;font-size:0.72rem;font-weight:500;color:#333;letter-spacing:0.04em;pointer-events:none;">Made by Safaan</div>
  <script>
    var jc = new URLSearchParams(location.search).get('join');
    if (jc && /^[A-Z]{4}$/i.test(jc)) localStorage.setItem('ttt_join', jc.toUpperCase());
  </script>
</body>
</html>"""


class GameWebSocketHandler(tornado.websocket.WebSocketHandler):
    def check_origin(self, origin):
        if not origin:
            return False
        normalized = origin.rstrip('/')
        if normalized in ALLOWED_ORIGINS:
            return True
        try:
            origin_host = urlparse(origin).netloc.lower()
        except ValueError:
            return False
        return bool(origin_host and origin_host == self.request.host.lower())

    def open(self):
        self.room_code = None
        self.role = None
        ticket = self.get_argument('ticket', '')
        ticket_data = ws_tickets.pop(ticket, None) if ticket else None
        if ticket_data and ticket_data[1] >= time.time():
            self.user_id = ticket_data[0]
        else:
            self.user_id = verify_request_user(self)
        if not self.user_id:
            self.close(code=4401, reason='Authentication required')
            return
        self.profile = get_profile(self.user_id) or {
            'id': self.user_id,
            'username': 'player',
            'displayName': 'Player',
            'profilePicture': '',
            'wins': 0,
            'losses': 0,
            'draws': 0,
        }

    def on_message(self, message):
        try:
            data = json.loads(message)
        except Exception:
            return
        if not isinstance(data, dict):
            safe_send(self, json.dumps({'type': 'error', 'message': 'Invalid message'}))
            return
        msg_type = data.get('type')
        if msg_type == 'create':
            self._handle_create()
        elif msg_type == 'join':
            self._handle_join(data.get('code', ''))
        elif msg_type == 'move':
            self._handle_move(data.get('index'))
        elif msg_type == 'restart':
            self._handle_restart()
        elif msg_type == 'chat':
            self._handle_chat(data.get('text', ''))
        elif msg_type in ('rtc_offer', 'rtc_answer', 'rtc_ice', 'rtc_ready'):
            self._relay_signal(data)

    def _handle_create(self):
        if not self.user_id or not self.profile:
            safe_send(self, json.dumps({'type': 'error', 'message': 'Complete your profile first'}))
            return
        if self.room_code and self.room_code in rooms:
            rooms.pop(self.room_code, None)
        code = None
        for _ in range(100):
            candidate = make_code()
            if candidate not in rooms:
                code = candidate
                break
        if code is None:
            safe_send(self, json.dumps({'type': 'error', 'message': 'Could not create a room'}))
            return
        rooms[code] = {
            'board': [None] * 9,
            'turn': 'X',
            'players': [self, None],
            'winner': None,
            'draw': False,
            'restart_votes': set(),
            'last_activity': time.time(),
        }
        self.room_code = code
        self.role = 'X'
        safe_send(self, json.dumps({'type': 'created', 'code': code}))

    def _handle_join(self, code):
        if not isinstance(code, str) or not re.fullmatch(r'[A-Za-z]{4}', code.strip()):
            safe_send(self, json.dumps({'type': 'error', 'message': 'Invalid room code'}))
            return
        if not self.user_id or not self.profile:
            safe_send(self, json.dumps({'type': 'error', 'message': 'Complete your profile first'}))
            return
        code = code.upper().strip()
        room = rooms.get(code)
        if not room:
            safe_send(self, json.dumps({'type': 'error', 'message': 'Room not found'}))
            return
        if room['players'][1] is not None:
            safe_send(self, json.dumps({'type': 'error', 'message': 'Room is full'}))
            return
        if room['players'][0] is self:
            safe_send(self, json.dumps({'type': 'error', 'message': 'You cannot join your own room twice'}))
            return
        room['players'][1] = self
        self.room_code = code
        self.role = 'O'
        room['last_activity'] = time.time()
        safe_send(self, json.dumps({'type': 'joined', 'code': code}))
        x_player = room['players'][0]
        o_player = room['players'][1]
        start_msg = json.dumps({
            'type': 'start',
            'board': room['board'],
            'currentPlayer': room['turn'],
            'xProfile': x_player.profile if x_player else None,
            'oProfile': o_player.profile if o_player else None,
        })
        broadcast(room, start_msg)

    def _handle_move(self, index):
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or not 0 <= index < 9
        ):
            safe_send(self, json.dumps({'type': 'error', 'message': 'Invalid move'}))
            return
        code = self.room_code
        room = rooms.get(code)
        if not room:
            return
        board = room['board']
        if room['winner'] or room['draw']:
            return
        if room['turn'] != self.role:
            return
        if board[index] is not None:
            return
        board[index] = self.role
        room['last_activity'] = time.time()
        winner, line = check_winner(board)
        draw = not winner and all(v is not None for v in board)
        if winner or draw:
            room['winner'] = winner
            room['draw'] = draw
            # Determine player IDs for stat recording
            x_player = room['players'][0]
            o_player = room['players'][1]
            x_id = x_player.user_id if x_player else None
            o_id = o_player.user_id if o_player else None
            winner_id = x_id if winner == 'X' else (o_id if winner == 'O' else None)
            loser_id  = o_id if winner == 'X' else (x_id if winner == 'O' else None)
            record_game_result(winner_id, loser_id, bool(draw), x_id, o_id)
            # Refresh profiles so restart messages carry updated stats
            if x_player and x_player.user_id:
                x_player.profile = get_profile(x_player.user_id)
            if o_player and o_player.user_id:
                o_player.profile = get_profile(o_player.user_id)
            broadcast(room, json.dumps({'type': 'gameover', 'board': board, 'winner': winner, 'line': line}))
        else:
            room['turn'] = 'O' if self.role == 'X' else 'X'
            broadcast(room, json.dumps({'type': 'update', 'board': board, 'currentPlayer': room['turn']}))

    def _handle_restart(self):
        code = self.room_code
        room = rooms.get(code)
        if not room:
            return
        if self.role not in ('X', 'O'):
            return
        room['restart_votes'].add(self.role)
        if len(room['restart_votes']) < 2:
            for player in room['players']:
                if player and player != self:
                    safe_send(player, json.dumps({'type': 'restart_waiting'}))
        else:
            room['board'] = [None] * 9
            room['turn'] = 'X'
            room['winner'] = None
            room['draw'] = False
            room['restart_votes'] = set()
            room['last_activity'] = time.time()
            x_player = room['players'][0]
            o_player = room['players'][1]
            broadcast(room, json.dumps({
                'type': 'start',
                'board': room['board'],
                'currentPlayer': room['turn'],
                'xProfile': x_player.profile if x_player else None,
                'oProfile': o_player.profile if o_player else None,
            }))

    def _handle_chat(self, text):
        if not isinstance(text, str):
            return
        text = text.strip()
        if not text:
            return
        text = text[:500]
        code = self.room_code
        room = rooms.get(code)
        if not room:
            return
        broadcast(room, json.dumps({'type': 'chat', 'from': self.role, 'text': text}))

    def _relay_signal(self, data):
        if not isinstance(data, dict) or data.get('type') not in (
            'rtc_offer', 'rtc_answer', 'rtc_ice', 'rtc_ready'
        ):
            return
        code = self.room_code
        room = rooms.get(code)
        if not room:
            return
        msg = json.dumps(data)
        for player in room['players']:
            if player and player != self:
                safe_send(player, msg)

    def on_close(self):
        code = self.room_code
        room = rooms.get(code)
        if not room:
            return
        for player in room['players']:
            if player and player != self:
                safe_send(player, json.dumps({'type': 'opponent_left', 'reason': 'Opponent disconnected.'}))
        rooms.pop(code, None)


class UserStatusHandler(AuthenticatedJsonHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Cache-Control', 'no-cache')

    def get(self):
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            'SELECT username, display_name, profile_picture FROM users WHERE clerk_id = ?', (self.user_id,)
        ).fetchone()
        conn.close()
        if row:
            self.write(json.dumps({'hasProfile': True, 'username': row[0], 'displayName': row[1], 'profilePicture': row[2]}))
        else:
            self.write(json.dumps({'hasProfile': False}))


class WebSocketTicketHandler(AuthenticatedJsonHandler):
    def post(self):
        now = time.time()
        for ticket, (_, expires_at) in list(ws_tickets.items()):
            if expires_at < now:
                ws_tickets.pop(ticket, None)
        ticket = secrets.token_urlsafe(32)
        ws_tickets[ticket] = (self.user_id, now + 30)
        self.write(json.dumps({'ticket': ticket}))


class UserCheckUsernameHandler(AuthenticatedJsonHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Cache-Control', 'no-cache')

    def get(self):
        username = self.get_argument('username', '').strip()
        if not username or not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            self.write(json.dumps({'available': False}))
            return
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute('SELECT 1 FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()
        conn.close()
        self.write(json.dumps({'available': row is None}))


class UserRegisterHandler(AuthenticatedJsonHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Cache-Control', 'no-cache')

    def post(self):
        data = parse_json_body(self)
        username = data.get('username', '')
        display_name = data.get('displayName', '')
        profile_picture = normalize_picture_url(data.get('profilePicture', ''))
        username = username.strip() if isinstance(username, str) else ''
        display_name = display_name.strip() if isinstance(display_name, str) else ''

        if not username or not display_name:
            self.set_status(400)
            self.write(json.dumps({'error': 'All fields required'}))
            return
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            self.set_status(400)
            self.write(json.dumps({'error': 'Username must be 3–20 characters: letters, numbers, underscores only'}))
            return
        if not is_safe_display_name(display_name):
            self.set_status(400)
            self.write(json.dumps({'error': 'Display name contains invalid characters or is too long'}))
            return
        if profile_picture is None:
            self.set_status(400)
            self.write(json.dumps({'error': 'Invalid profile picture URL'}))
            return

        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute(
                'INSERT INTO users (clerk_id, username, display_name, profile_picture, created_at) VALUES (?, ?, ?, ?, ?)',
                (self.user_id, username, display_name, profile_picture, int(time.time()))
            )
            conn.commit()
            self.write(json.dumps({'ok': True}))
        except sqlite3.IntegrityError as exc:
            self.set_status(409)
            if 'users.clerk_id' in str(exc):
                self.write(json.dumps({'error': 'Profile already exists'}))
            else:
                self.write(json.dumps({'error': 'Username has been taken'}))
        finally:
            conn.close()


class UserListHandler(AuthenticatedJsonHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Cache-Control', 'no-cache')

    def get(self):
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            'SELECT clerk_id, username, display_name, profile_picture, wins, losses, draws FROM users ORDER BY wins DESC, created_at DESC'
        ).fetchall()
        conn.close()
        users = [{'id': r[0], 'username': r[1], 'displayName': r[2], 'profilePicture': r[3], 'wins': r[4], 'losses': r[5], 'draws': r[6]} for r in rows]
        self.write(json.dumps(users))


class PublicLeaderboardHandler(JsonHandler):
    def get(self):
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            'SELECT username, display_name, wins, losses, draws FROM users ORDER BY wins DESC, created_at DESC'
        ).fetchall()
        conn.close()
        users = [
            {
                'username': r[0],
                'displayName': r[1],
                'wins': r[2],
                'losses': r[3],
                'draws': r[4],
            }
            for r in rows
        ]
        self.write(json.dumps(users))


class FriendRequestHandler(AuthenticatedJsonHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Cache-Control', 'no-cache')

    def post(self):
        data = parse_json_body(self)
        to_id = data.get('toId', '')
        to_id = to_id.strip() if isinstance(to_id, str) else ''
        from_id = self.user_id
        if not to_id or from_id == to_id:
            self.set_status(400)
            self.write(json.dumps({'error': 'Invalid request'}))
            return
        conn = sqlite3.connect(DB_PATH)
        try:
            target_exists = conn.execute(
                'SELECT 1 FROM users WHERE clerk_id=?', (to_id,)
            ).fetchone()
            if not target_exists:
                self.set_status(404)
                self.write(json.dumps({'error': 'Player not found'}))
                return
            existing = conn.execute(
                'SELECT status FROM friends WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)',
                (from_id, to_id, to_id, from_id)
            ).fetchone()
            if existing:
                self.set_status(409)
                self.write(json.dumps({'error': 'Already friends or request pending', 'status': existing[0]}))
                return
            conn.execute(
                'INSERT INTO friends (from_id, to_id, status, created_at) VALUES (?, ?, "pending", ?)',
                (from_id, to_id, int(time.time()))
            )
            conn.commit()
            self.write(json.dumps({'ok': True}))
        except sqlite3.IntegrityError:
            self.set_status(409)
            self.write(json.dumps({'error': 'Request already sent'}))
        finally:
            conn.close()


class FriendRespondHandler(AuthenticatedJsonHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Cache-Control', 'no-cache')

    def post(self):
        data = parse_json_body(self)
        user_id = self.user_id
        from_id = data.get('fromId', '')
        from_id = from_id.strip() if isinstance(from_id, str) else ''
        accept = data.get('accept', False)
        if not from_id or not isinstance(accept, bool):
            self.set_status(400)
            self.write(json.dumps({'error': 'Invalid request'}))
            return
        conn = sqlite3.connect(DB_PATH)
        try:
            if accept:
                cursor = conn.execute(
                    'UPDATE friends SET status="accepted" WHERE from_id=? AND to_id=? AND status="pending"',
                    (from_id, user_id)
                )
            else:
                cursor = conn.execute(
                    'DELETE FROM friends WHERE from_id=? AND to_id=? AND status="pending"',
                    (from_id, user_id)
                )
            conn.commit()
            if cursor.rowcount:
                self.write(json.dumps({'ok': True}))
            else:
                self.set_status(404)
                self.write(json.dumps({'error': 'Pending request not found'}))
        finally:
            conn.close()


class FriendListHandler(AuthenticatedJsonHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Cache-Control', 'no-cache')

    def get(self):
        user_id = self.user_id
        conn = sqlite3.connect(DB_PATH)
        # Friends (accepted)
        friends_rows = conn.execute('''
            SELECT u.clerk_id, u.username, u.display_name, u.profile_picture, u.wins, u.losses, u.draws
            FROM friends f JOIN users u ON (
                CASE WHEN f.from_id = ? THEN f.to_id ELSE f.from_id END = u.clerk_id
            )
            WHERE (f.from_id = ? OR f.to_id = ?) AND f.status = "accepted"
        ''', (user_id, user_id, user_id)).fetchall()
        # Incoming pending requests
        incoming_rows = conn.execute('''
            SELECT u.clerk_id, u.username, u.display_name, u.profile_picture, u.wins, u.losses, u.draws
            FROM friends f JOIN users u ON f.from_id = u.clerk_id
            WHERE f.to_id = ? AND f.status = "pending"
        ''', (user_id,)).fetchall()
        # Outgoing pending
        outgoing_rows = conn.execute('''
            SELECT to_id FROM friends WHERE from_id = ? AND status = "pending"
        ''', (user_id,)).fetchall()
        conn.close()

        def row_to_dict(r):
            return {'id': r[0], 'username': r[1], 'displayName': r[2], 'profilePicture': r[3], 'wins': r[4], 'losses': r[5], 'draws': r[6]}

        self.write(json.dumps({
            'friends': [row_to_dict(r) for r in friends_rows],
            'incoming': [row_to_dict(r) for r in incoming_rows],
            'outgoing': [r[0] for r in outgoing_rows],
        }))


class ChallengeSendHandler(AuthenticatedJsonHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Cache-Control', 'no-cache')

    def post(self):
        data = parse_json_body(self)
        from_id = self.user_id
        to_id = data.get('toId', '')
        room_code = data.get('roomCode', '')
        to_id = to_id.strip() if isinstance(to_id, str) else ''
        room_code = room_code.strip().upper() if isinstance(room_code, str) else ''
        if not to_id or not re.fullmatch(r'[A-Z]{4}', room_code):
            self.set_status(400)
            self.write(json.dumps({'error': 'A player and valid room code are required'}))
            return
        conn = sqlite3.connect(DB_PATH)
        try:
            profile = get_profile(from_id)
            friendship = conn.execute(
                '''SELECT 1 FROM friends
                   WHERE ((from_id=? AND to_id=?) OR (from_id=? AND to_id=?))
                     AND status="accepted"''',
                (from_id, to_id, to_id, from_id),
            ).fetchone()
            room = rooms.get(room_code)
            if not profile:
                self.set_status(400)
                self.write(json.dumps({'error': 'Complete your profile first'}))
                return
            if not friendship:
                self.set_status(403)
                self.write(json.dumps({'error': 'You can only challenge friends'}))
                return
            if not room or not room['players'][0] or room['players'][0].user_id != from_id:
                self.set_status(400)
                self.write(json.dumps({'error': 'Create this room before sending the challenge'}))
                return
            # Remove any previous pending challenge between these two users
            conn.execute(
                'DELETE FROM challenges WHERE from_id=? AND to_id=? AND status="pending"',
                (from_id, to_id)
            )
            conn.execute(
                'INSERT INTO challenges (from_id, to_id, room_code, from_name, from_pic, status, created_at) VALUES (?,?,?,?,?,"pending",?)',
                (
                    from_id,
                    to_id,
                    room_code,
                    profile['displayName'],
                    profile['profilePicture'],
                    int(time.time()),
                )
            )
            conn.commit()
            self.write(json.dumps({'ok': True}))
        finally:
            conn.close()


class ChallengeIncomingHandler(AuthenticatedJsonHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Cache-Control', 'no-cache')

    def get(self):
        user_id = self.user_id
        cutoff = int(time.time()) - 300  # 5-minute expiry
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            '''SELECT id, from_id, room_code, from_name, from_pic, created_at
               FROM challenges
               WHERE to_id=? AND status="pending" AND room_code != "" AND created_at > ?
               ORDER BY created_at DESC LIMIT 5''',
            (user_id, cutoff)
        ).fetchall()
        conn.close()
        challenges = [
            {'id': r[0], 'fromId': r[1], 'roomCode': r[2], 'fromName': r[3], 'fromPic': r[4], 'createdAt': r[5]}
            for r in rows
        ]
        self.write(json.dumps(challenges))


class ChallengeDismissHandler(AuthenticatedJsonHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Cache-Control', 'no-cache')

    def post(self):
        data = parse_json_body(self)
        challenge_id = data.get('challengeId')
        if not isinstance(challenge_id, int) or isinstance(challenge_id, bool) or challenge_id <= 0:
            self.set_status(400)
            self.write(json.dumps({'error': 'challengeId required'}))
            return
        conn = sqlite3.connect(DB_PATH)
        try:
            cursor = conn.execute(
                'UPDATE challenges SET status="dismissed" WHERE id=? AND to_id=?',
                (challenge_id, self.user_id),
            )
            conn.commit()
            if cursor.rowcount:
                self.write(json.dumps({'ok': True}))
            else:
                self.set_status(404)
                self.write(json.dumps({'error': 'Challenge not found'}))
        finally:
            conn.close()


class DonateTapHandler(JsonHandler):
    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Cache-Control', 'no-cache')

    def post(self):
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute('INSERT INTO donate_taps (created_at) VALUES (?)', (int(time.time()),))
            conn.commit()
            count = conn.execute('SELECT COUNT(*) FROM donate_taps').fetchone()[0]
            self.write(json.dumps({'ok': True, 'count': count}))
        finally:
            conn.close()

    def get(self):
        conn = sqlite3.connect(DB_PATH)
        count = conn.execute('SELECT COUNT(*) FROM donate_taps').fetchone()[0]
        conn.close()
        self.write(json.dumps({'count': count}))


class LandingHandler(PageHandler):
    def get(self):
        self.set_header('Content-Type', 'text/html; charset=utf-8')
        self.set_header('Cache-Control', 'no-cache')
        self.write(LANDING_HTML)


class ReactAppHandler(PageHandler):
    def get(self, path=None):
        self.set_header('Cache-Control', 'no-cache')
        self.set_header('Content-Type', 'text/html; charset=utf-8')
        with open(os.path.join(APP_ROOT, 'index.html'), 'rb') as f:
            self.write(f.read())


class GuestHandler(PageHandler):
    def get(self):
        self.set_header('Cache-Control', 'no-cache')
        self.set_header('Content-Type', 'text/html; charset=utf-8')
        with open(os.path.join(APP_ROOT, 'guest.html'), 'rb') as f:
            self.write(f.read())


class StaticFileHandler(tornado.web.StaticFileHandler):
    def set_extra_headers(self, path):
        self.set_header('X-Content-Type-Options', 'nosniff')
        self.set_header('Referrer-Policy', 'same-origin')
        if path.startswith('assets/'):
            self.set_header('Cache-Control', 'public, max-age=31536000, immutable')
        else:
            self.set_header('Cache-Control', 'public, max-age=3600')


class NotFoundHandler(JsonHandler):
    def prepare(self):
        self.set_status(404)
        self.finish(json.dumps({'error': 'Not found'}))


def make_app():
    return tornado.web.Application([
        (r'/', ReactAppHandler),
        (r'/welcome', LandingHandler),
        (r'/guest\.html', GuestHandler),
        (r'/sign-in(?:/.*)?', ReactAppHandler),
        (r'/sign-up(?:/.*)?', ReactAppHandler),
        (r'/api/ws', GameWebSocketHandler),
        (r'/api/ws-ticket', WebSocketTicketHandler),
        (r'/api/user/status', UserStatusHandler),
        (r'/api/user/check-username', UserCheckUsernameHandler),
        (r'/api/user/register', UserRegisterHandler),
        (r'/api/users', UserListHandler),
        (r'/api/leaderboard', PublicLeaderboardHandler),
        (r'/api/friends', FriendListHandler),
        (r'/api/friends/request', FriendRequestHandler),
        (r'/api/friends/respond', FriendRespondHandler),
        (r'/api/challenges/send', ChallengeSendHandler),
        (r'/api/challenges/incoming', ChallengeIncomingHandler),
        (r'/api/challenges/dismiss', ChallengeDismissHandler),
        (r'/api/donate/tap', DonateTapHandler),
        (
            r'/(assets/.*)',
            StaticFileHandler,
            {'path': APP_ROOT},
        ),
        (
            r'/(favicon\.svg|logo\.svg|opengraph\.jpg|robots\.txt)',
            StaticFileHandler,
            {'path': APP_ROOT},
        ),
    ], default_handler_class=NotFoundHandler)


async def cleanup_loop():
    while True:
        await asyncio.sleep(300)
        now = time.time()
        stale = [c for c, r in list(rooms.items()) if now - r['last_activity'] > 1800]
        for c in stale:
            rooms.pop(c, None)


if __name__ == '__main__':
    app = make_app()
    app.listen(PORT, address=os.environ.get('HOST', '0.0.0.0'))
    print(f'Serving on port {PORT}')
    loop = tornado.ioloop.IOLoop.current()
    loop.asyncio_loop.create_task(cleanup_loop())
    loop.start()
