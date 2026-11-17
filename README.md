# Sentry Hub

A role-based login system for organisations: salted + peppered passwords, a one-time code emailed at every sign-in, three role dashboards (admin, staff, user), soft-delete with restore, and encrypted backups to AWS S3. Built with Flask for Vercel, with Neon Postgres as the database.

## What it does

| Area | How it works |
|---|---|
| **Identification** | Unique username + email per account. Sign in with either. |
| **Passwords** | Per-user random **salt** (stored in the DB) + one secret **pepper** (only in an environment variable). Password → HMAC-SHA256 with the pepper → scrypt with the salt. |
| **2FA** | After the password is accepted, a 6-digit code is emailed (Gmail SMTP). It expires in 10 minutes, works once, is stored hashed, and is cancelled after 5 wrong tries. Resend has a 30 s cooldown. |
| **Roles** | `admin`, `staff`, `user` — each with its own dashboard. Every route is checked on the server. |
| **Admin** | Sees all accounts (including deleted ones, labelled **Deleted**) with each account's salt and password hash. Can switch people between `user` and `staff`, restore deleted accounts, and run backups. |
| **Staff** | Sees active users only and can delete them. A deleted account leaves the staff list immediately, can't sign in, and any open session is ended. |
| **Backups** | **Back up now** button (shows "Backup successful" only after S3 confirms the upload; otherwise shows the error) plus a daily Vercel Cron job. Snapshots are gzip-compressed and encrypted before upload. |

Other protections: CSRF tokens on every form, lockout after 5 wrong passwords (15 min), generic login errors, constant-time comparisons, HttpOnly + Secure + SameSite cookies, strict Content-Security-Policy and other security headers.

## Deploy to Vercel (about 15 minutes)

### 1. Neon (database)
1. Create a project at [neon.tech](https://neon.tech).
2. Copy the **pooled** connection string (the host contains `-pooler`). This is your `DATABASE_URL`.
3. Optional: paste `schema.sql` into Neon's SQL Editor and run it. (The app creates the tables itself on first start.)

### 2. Gmail (verification emails)
1. Turn on 2-Step Verification for the Gmail account that will send the codes.
2. Google Account → Security → **App passwords** → create one. Copy the 16-character password.
3. `SMTP_USER` = that Gmail address, `SMTP_PASSWORD` = the app password. (Gmail allows roughly 500 emails/day.)

### 3. AWS S3 (backups)
1. Use your existing bucket. Create an IAM user with only this permission (replace `YOUR-BUCKET`):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": "s3:PutObject",
       "Resource": "arn:aws:s3:::YOUR-BUCKET/sentry-hub/backups/*"
     }]
   }
   ```
2. Create an access key for that user.
3. Note: Vercel reserves the plain `AWS_*` variable names, so this app uses `BACKUP_AWS_*`.

### 4. Generate three secrets
Run this three times (SECRET_KEY, PEPPER, CRON_SECRET) plus once more for BACKUP_PASSPHRASE:
```
python3 -c "import secrets; print(secrets.token_hex(32))"
```
> **Never change the PEPPER after people have registered.** All existing passwords would stop working. Keep a safe copy of it and of the BACKUP_PASSPHRASE (without it, backups can't be opened).

### 5. Push to GitHub and import into Vercel
1. Create a GitHub repository and push this folder.
2. In Vercel: **Add New → Project →** import the repo. Framework preset can stay "Other".
3. Add the environment variables below (Project → Settings → Environment Variables), then deploy.

| Variable | Value |
|---|---|
| `SECRET_KEY` | random 64-hex string |
| `PEPPER` | random 64-hex string |
| `DATABASE_URL` | Neon pooled connection string |
| `ADMIN_USERNAME`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` | your first admin (created on first start if no admin exists) |
| `SMTP_USER`, `SMTP_PASSWORD` | Gmail address + app password |
| `BACKUP_S3_BUCKET` | your bucket name |
| `BACKUP_AWS_REGION` | e.g. `eu-west-2` |
| `BACKUP_AWS_ACCESS_KEY_ID`, `BACKUP_AWS_SECRET_ACCESS_KEY` | the IAM user's key |
| `BACKUP_PASSPHRASE` | random string used to encrypt backups |
| `CRON_SECRET` | random string — Vercel sends it automatically to the cron job |

Optional: `MAIL_FROM`, `SMTP_HOST`, `SMTP_PORT`, `BACKUP_S3_PREFIX`, `SESSION_HOURS`.

### 6. First sign-in
Open your site, sign in as the admin (the code arrives by email), and then **delete `ADMIN_PASSWORD` from Vercel's environment variables**. It is only needed once.

### Checking it works
- Sign in as admin → click **Back up now**. You should see "Backup successful" and a new object in your bucket under `sentry-hub/backups/`.
- Vercel → Project → Settings → Cron Jobs shows the daily job (03:00 UTC). On the free Hobby plan, cron runs once a day at most, with timing accurate to within the hour.

## Opening a backup
Download the `.enc` file from S3, then:
```
pip install cryptography
python scripts/decrypt_backup.py sentry-hub-20261117T030000Z.json.gz.enc
```
It asks for `BACKUP_PASSPHRASE` and writes a JSON file with every row of the users table (including salts and hashes).

## Run locally
```
pip install -r requirements.txt
python dev.py
```
Open http://localhost:5000. Local mode uses a SQLite file, prints the emailed codes in the terminal, and creates `admin` / `Admin12345!`. Run the tests with `python -m unittest discover -s tests`.

## Project layout
```
api/index.py        Vercel entry point
sentryhub/          app code (auth, dashboards, security, backup, mailer, db)
templates/ static/  pages, styles, scripts
schema.sql          Neon schema
vercel.json         routing + daily backup cron
tests/              automated tests
```

## Good to know
- Admins can see password **hashes** by design. They are salted and peppered, so they can't be reversed, but treat admin accounts as highly privileged.
- Email is the only second factor. Anyone who controls a user's inbox and knows their password can sign in as them.
- New sign-ups are always `user`. Only an admin can promote someone to `staff`; there is no screen to create more admins.
