# CIT HOD Office Desk (Vercel)

Task, leave, misconduct and records system for the CIT department, GCT Kamalia.
Roles: **staff**, **admin (HOD)**, **super admin**.

## Deploy in about 10 minutes
1. Create a free Postgres database at https://neon.tech (or Vercel > Storage > Neon). Copy the connection string.
2. Upload this folder to a GitHub repository.
3. In Vercel choose **Add New > Project**, import the repository, framework preset **Other**.
4. Under **Environment Variables** add:
   - `DATABASE_URL` the Neon connection string
   - `AUTH_SECRET` a random string of 32+ characters
   - `SUPERADMIN_USER` and `SUPERADMIN_PASS` your first super admin login
5. Click **Deploy**. Tables are created automatically on the first request.
6. Open the site and sign in as the super admin. Under **Staff & accounts** create the HOD (admin) account and each teacher.

After the first login you may remove `SUPERADMIN_PASS` from Vercel. It is only used while the database has no users.

## Who can do what
- **Staff:** see only their own tasks, update status, add a note and an optional photo, apply for leave.
- **Admin (HOD):** create staff, assign tasks to one, selected or all staff, approve leave, record leave, file misconduct reports, export all reports.
- **Super admin:** everything above, plus create admin and super admin accounts, delete misconduct reports, export the accounts list.

## Reports
Task records, staff performance summary, leave, misconduct, accounts: view as a table, download CSV (opens in Excel), download JSON, or print / save as PDF.

## Notes
- Passwords are hashed with scrypt. Sessions are signed HttpOnly cookies that last 12 hours.
- Photos are resized in the browser (about 900 px) and stored in the database.
- Staff cannot change their own password yet; an admin resets it from Staff & accounts.
- Reminders show as overdue and due items on the dashboard. Sending WhatsApp or SMS automatically needs a separate service.
