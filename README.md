# CampusPass – Student Event Ticketing System
Node.js + Express + SQLite backend, vanilla JS frontend (violet/pink design system, Plus Jakarta Sans).

## Run
    npm install
    npm start        # http://localhost:3000

Demo logins (password `password123`): amani@students.ac.ke (student), organizer@students.ac.ke, admin@campus.ac.ke.
Set `JWT_SECRET` in production.

## Features
Auth (JWT, bcrypt) · search/filter events · booking with capacity check + unique QR · QR validation (blocks reuse) ·
organizer dashboard + event creation · admin approvals, user suspension, audit log.
