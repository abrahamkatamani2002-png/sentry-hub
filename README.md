# Sentry Hub

A role-based login system for organisations: salted + peppered passwords, a one-time code emailed at every sign-in, three role dashboards (admin, staff, user), member invitations, a restore bin for deleted members, an activity log, a notice board, and encrypted backups (stored in the database, or AWS S3 if you add it). Built with Flask for Vercel, with Neon Postgres as the database.

## What it does

| Area | How it works |
|---|---|
| **Identification** | Unique username + email per account. Sign in with either. |
| **Passwords** | Per-user random **salt** (stored in the DB) + one secret **pepper** (only in an environment variable). Password → HMAC-SHA256 with the pepper → scrypt with the salt. |
| **2FA** | After the password is accepted, a 6-digit code is emailed (Gmail SMTP). It expires in 10 minutes, works once, is stored hashed, and is cancelled after 5 wrong tries. |
| **Roles** | `admin`, `staff`, `user`, each with its own dashboard. Every route is checked on the server. |
| **Adding members** | Admin adds a member (name, username, email, role: staff or user). The member gets an emailed link (valid 48 hours, works once) to set their own password. The admin never sees or types it. |
| **Delete and restore** | Admin can delete any user or staff member; staff can delete users. Nothing is erased: deleted members move to **Deleted members** with who deleted them and when, and the admin restores them with one click (same role, same details, same password). Deleted members cannot sign in, and open sessions end immediately. |
| **Roles** | Admin can switch members between `user` and `staff`. Admin accounts can't be created or deleted from the dashboard. |
| **Forgot password** | Emailed reset link (valid 1 hour, works once). The page never reveals whether an email is registered. |
| **Activity log** | Admin-only list of sign-ins, failed sign-ins, member changes, password changes, backups and announcements. |
| **Notice board** | Admin and staff post announcements (optionally pinned). Every member sees them on their dashboard. Staff manage their own posts; admin manages all. |
| **User dashboard** | Time-of-day greeting, editable profile (job title, bio, avatar colour), an account-health score with checklist, your last five sign-ins, and the notice board. |
| **Backups** | **Back up now** button (shows "Backup completed" only after S3 confirms the upload, otherwise the error) plus a daily Vercel Cron job. Snapshots are gzip-compressed and encrypted before upload. |

Other protections: CSRF tokens on every form, lockout after 5 wrong passwords (15 min), generic login errors, constant-time comparisons, HttpOnly + Secure + SameSite cookies, strict Content-Security-Policy and other security headers.

## Upgrading an existing deployment

1. Copy the new files over your repository folder (keep your `.git` folder), then:
   ```
   git add .
   git commit -m "Add member management, restore bin, activity log, notices"
   git push
   ```
   Vercel redeploys automatically.
2. The first request after deploying upgrades your Neon database by itself: it adds the new tables and columns and **keeps every existing account and password**.
3. If you'd rather do it by hand, paste `schema.sql` into Neon's SQL Editor and run it. It is safe to run more than once.
4. Optional: add the environment variable `PUBLIC_URL` (your site's address, e.g. `https://my-site.vercel.app`) so emailed links always use your exact address.

## Deploy to Vercel (first time)

### 1. Neon (database)
1. Create a project at [neon.tech](https://neon.tech).
2. Copy the **pooled** connection string (the host contains `-pooler`). This is your `DATABASE_URL`.
3. Optional: paste `schema.sql` into Neon's SQL Editor and run it. (The app creates the tables itself on first start.)

### 2. Gmail (verification and invitation emails)
1. Turn on 2-Step Verification for the Gmail account that will send the emails.
2. Google Account → Security → **App passwords** → create one. Copy the 16-character password.
3. `SMTP_USER` = that Gmail address, `SMTP_PASSWORD` = the app password. (Gmail allows roughly 500 emails/day.)

### 3. AWS S3 (backups, optional until you're ready)
1. Create an IAM user with only this permission (replace `YOUR-BUCKET`):
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
3. Vercel reserves the plain `AWS_*` variable names, so this app uses `BACKUP_AWS_*`.

### 4. Generate your secrets
Run this once per secret (SECRET_KEY, PEPPER, CRON_SECRET, BACKUP_PASSPHRASE):
```
python3 -c "import secrets; print(secrets.token_hex(32))"
```
On Windows PowerShell:
```
$b = New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); ($b | ForEach-Object { $_.ToString("x2") }) -join ""
```
> **Never change the PEPPER after people have registered.** All existing passwords would stop working. Keep a safe copy of it and of the BACKUP_PASSPHRASE (without it, backups can't be opened).

### 5. Push to GitHub and import into Vercel
1. Push this folder to a GitHub repository (the folder with `vercel.json` at the top).
2. In Vercel: **Add New → Project →** import the repo. Framework preset: "Other".
3. Add the environment variables below, then deploy.

| Variable | Value |
|---|---|
| `SECRET_KEY` | random 64-hex string |
| `PEPPER` | random 64-hex string |
| `DATABASE_URL` | Neon pooled connection string |
| `ADMIN_USERNAME`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` | your first admin (created on first start if no admin exists). Use an email you can open. |
| `SMTP_USER`, `SMTP_PASSWORD` | Gmail address + app password |
| `BACKUP_PASSPHRASE` | random string used to encrypt backups |
| `CRON_SECRET` | random string. Vercel sends it automatically to the cron job |
| `BACKUP_S3_BUCKET`, `BACKUP_AWS_REGION`, `BACKUP_AWS_ACCESS_KEY_ID`, `BACKUP_AWS_SECRET_ACCESS_KEY` | your S3 bucket and IAM key (when you're ready for backups) |

Optional: `PUBLIC_URL`, `MAIL_FROM`, `SMTP_HOST`, `SMTP_PORT`, `BACKUP_S3_PREFIX`, `SESSION_HOURS`.

### 6. First sign-in
Open your site, sign in as the admin (the code arrives by email), then **delete `ADMIN_PASSWORD` from Vercel's environment variables**. It is only needed once.

### Checking it works
- Admin → **Add member**: add yourself with a second email address; the invitation should arrive and the link should let you set a password.
- Delete that member, then open **Deleted members** and restore them.
- With AWS set up: **Back up now** should show "Backup successful" and a new object should appear in your bucket under `sentry-hub/backups/`.

## Opening a backup
Backups are kept inside your Neon database by default (latest 30; use **Download** next to the latest attempt on the admin page). If you later add the AWS settings, new backups go to S3 instead. A file downloaded from the dashboard is opened the same way as one from S3.
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
Open http://localhost:5000. Local mode uses a SQLite file, prints emailed codes and links in the terminal, and creates `admin` / `Admin12345!`. Run the tests with `python -m unittest discover -s tests`.

## Project layout
```
api/index.py        Vercel entry point
sentryhub/          app code (auth, dashboards, notices, activity, invites, security, backup, mailer, db)
templates/ static/  pages, styles, scripts
schema.sql          Neon schema + upgrade
vercel.json         routing + daily backup cron
tests/              automated tests
```

## Good to know
- Admins can see password **hashes** by design. They are salted and peppered, so they can't be reversed, but treat admin accounts as highly privileged.
- Email is the only second factor. Anyone who controls a user's inbox and knows their password can sign in as them.
- New sign-ups are always `user`. Only an admin can promote someone to `staff`; there is no screen to create more admins.
- Deleted members are kept until restored. There is no "delete permanently" button in this version.
