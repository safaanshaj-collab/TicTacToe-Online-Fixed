# Tic Tac Toe — fixed build

This is the cleaned and secured version of the Tic Tac Toe website.

## Run locally

1. Install Python 3.11 or newer.
2. Open a terminal in this folder.
3. Install dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

4. Start the server:

   ```bash
   python server.py
   ```

5. Open `http://localhost:5000`.

The SQLite database is created automatically. No user database is included in
this ZIP.

## Deployment settings

The server reads the hosting platform's `PORT` automatically.

For a public deployment, set these environment variables:

- `CLERK_ISSUER`: the Clerk Frontend API URL.
- `CLERK_AUTHORIZED_PARTIES`: the exact public origin, such as
  `https://example.com`.
- `ALLOWED_ORIGINS`: the same public origin for WebSocket origin checks.
- `DB_PATH`: an optional persistent path for `users.db`.

Do not upload `.git`, `.env`, an existing `users.db`, or secret keys.

## Security changes

- Clerk session JWTs are verified on protected API and WebSocket requests.
- User IDs supplied by the browser are no longer trusted.
- Only required public assets are served.
- HTML rendering and profile-picture URLs are validated.
- Room codes, moves, chat messages, friend actions, and challenges are checked.
- The share button uses the current website address.
