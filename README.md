# Drop Space — Private File Sharing

A one-off file transfer app with self-service accounts. Account password hashes, uploaded file bytes, share-link metadata, sessions, and download counts are persisted in MongoDB. Every account has an isolated dashboard, 50 MB storage quota, and 20-upload rolling hourly limit.

## Data flow

1. A user creates an account or signs in on the branded login page. Passwords are salted and hashed with Node.js scrypt; successful authentication creates an opaque, random, HTTP-only, same-site session whose hash and expiry are stored in MongoDB.
2. The signed-in user selects or drops a file and chooses an expiry preset or custom date and time.
3. The server enforces a 10 MB file limit, a 50 MB per-account storage quota, and a rolling maximum of 20 successful uploads per account per hour.
4. The server validates the upload size and expiry, then saves the file bytes and metadata to MongoDB.
5. MongoDB stores the file bytes and metadata together. Share tokens are 256-bit random values with a unique index. Every share-page and download request checks expiry and revoke state on the server.
6. A successful download increments the count in MongoDB. Each account can copy links, change expiry, revoke, or delete only its own shares.

Downloads are delivered as opaque attachments and are never executed or rendered by the app. The app does not scan uploads for malware.

## Configure

1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env`.
3. In `.env`, set `MONGODB_URI` to your MongoDB Atlas connection string. Configure the Atlas database user and network access list so this machine can connect. `OWNER_USERNAME` and `OWNER_PASSWORD` create the initial account once; new users can register from the login page.
4. Install the dependencies and start the app:

```powershell
npm install
npm start
```

Open `http://127.0.0.1:3000/login` and create an account or sign in. The initial account uses `OWNER_USERNAME` and `OWNER_PASSWORD` from `.env`. If port 3000 is occupied, set `PORT=3001` in `.env` and open `http://127.0.0.1:3001/login`.

Set `COOKIE_SECURE=true` only when serving the app over HTTPS.

## Deploy to Vercel

The Vercel adapter is in `api/[...path].js` and `vercel.json`. Files are uploaded to MongoDB in 3 MB pieces and downloaded the same way so the app can retain its 10 MB file limit within Vercel Function payload limits. Temporary upload pieces expire automatically after 30 minutes.

1. Push this project to a private GitHub repository. `.gitignore` excludes `.env`, `data/`, and `node_modules/`; do not add secrets to source control.
2. In Vercel, choose **Add New → Project** and import the repository. Keep the detected Node.js settings; no custom build or output directory is needed.
3. Add `MONGODB_URI`, `MONGODB_DB_NAME`, `OWNER_USERNAME`, `OWNER_PASSWORD`, and `COOKIE_SECURE=true` in the project's environment variables. Do not set `PORT` or `HOST` on Vercel.
4. In Atlas, allow connections from the Vercel deployment. Vercel outbound IPs are dynamic by default; stable Static IPs are a Pro/Enterprise feature. For a Hobby deployment, a broad Atlas IP access entry may be needed, so use a unique, strong database password and a database user scoped to this app's database.
5. Deploy. After the first deployment, create an account from the login page or sign in with the initial credentials configured in the environment variables.

The app's file bytes and metadata remain in MongoDB Atlas. Temporary upload chunks are stored in `pending_uploads` and `upload_chunks` and removed when an upload completes; TTL indexes clean up abandoned uploads. Vercel's filesystem is not used for persistent uploads.

## MongoDB collections

- `files` stores each file's binary data, owner, original safe filename, size, creation/expiry times, token, revoke state, and download count.
- `sessions` stores hashed session IDs and their expiry. MongoDB removes expired sessions with a TTL index.
- `users` stores normalized usernames and per-account salted scrypt password hashes. Passwords are never stored in plaintext.
- `pending_uploads` and `upload_chunks` temporarily hold Vercel-sized upload parts; TTL indexes remove abandoned parts.
- `app_control` records one-time migration status.

The app does not silently fall back to local storage. New uploads and state changes are acknowledged only after MongoDB writes complete.

## Existing local uploads

On first startup, the app imports the old local `data/metadata.json` and matching files from `data/files/` into MongoDB, once per database. It leaves the old local files untouched as a backup. After confirming the imported files and links in the dashboard, you can archive or delete the old local `data/` folder.

## Features and limits

- Self-service registration and sign-in, scrypt password verification, an eight-hour HttpOnly/SameSite session, logout, and rate-limited authentication attempts.
- Per-account isolation: users only see and manage their own shares and quotas.
- 10 MB maximum per upload; 50 MB per-account quota; 20 successful uploads per account in a rolling hour.
- Expiry presets from 1 hour to 7 days and custom expiry from 1 minute up to 30 days.
- Owner can edit the expiry of an existing non-revoked share; the selected time is interpreted in the browser's local timezone and saved as UTC.
- Dashboard timestamps show the browser's timezone, while MongoDB Compass displays stored dates in UTC.
- One-off share page, attachment download, live download count, revoke, delete, filename search, and quota meter.
- Files are stored and delivered as downloads; this demo does not include malware scanning.

## Demo checklist

1. Sign in, upload a small file, and create a share link.
2. Copy the share link and download it in a private browser window.
3. Refresh the dashboard and confirm the download count increments.
4. Revoke the link and confirm the recipient gets a revoked message.
5. Create a custom expiry and verify the link expires at the selected time.
6. Restart the server and confirm files and metadata remain available from MongoDB.
