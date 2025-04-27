# Project Logger

**Secure command-line tool for logging project hours, managing research projects, and tracking goals.**

---

## Overview

Project Logger is a command-line application designed for research teams to securely log, track, and manage time spent on various projects. Built with a simple Python CLI frontend and a MariaDB backend, it supports role-based access control, session security, and atomic transaction handling.

---

## Features

- Secure user signup, login, and logout
- Clock-in and clock-out project time logging
- Role-based access: users and advisors
- Advisors can create, assign, and manage projects
- Weekly hour goal tracking for projects
- Personal and team time summaries
- Persistent sessions via token authentication
- Passwords securely hashed with bcrypt
- Atomic transactions to enforce data integrity

---

## Architecture

- **Frontend:** Python CLI (argparse)
- **Backend:** MariaDB database
- **Session Storage:** Secure local file (~/.projectlog_session) + database

---

## Database Schema

- **People:** Stores users, advisors, hashed passwords, session tokens
- **Projects:** Stores project names and weekly hour goals
- **Assigned:** Links users to projects (with supervisor flag)
- **Log:** Stores clock-in and clock-out sessions

---

## Main Commands

### User Commands
- `signup --username USERNAME --role [user|advisor]`
- `login --username USERNAME`
- `logout`
- `clock-in --project-id ID`
- `clock-out`
- `my-projects`
- `view-logs`
- `time-summary --project-id ID`

### Advisor-Only Commands
- `add-project --name NAME --goal HOURS`
- `delete-project --project-id ID`
- `assign-user --project-id ID --username USERNAME --supervisor [true|false]`
- `remove-user --project-id ID --username USERNAME`
- `delete-user --username USERNAME`
- `advisor-projects`
- `view-team`
- `check-goal --project-id ID`
- `weekly-report`

(Advisors can also use all user commands.)

---

## Security

- Passwords hashed with bcrypt
- Session tokens stored with strict file permissions
- Role-checked access for sensitive commands
- Double clock-in, clock-out without clock-in, and cross-project actions are prevented

---

## Example Workflow

1. Advisor signs up and creates a project
2. Advisor assigns users to the project
3. Users clock in and out of assigned projects
4. Advisors monitor progress and check if weekly goals are met

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/superde1fin/project-logger.git
   cd project-logger
   ```

2. Run the `configure` script with superuser privileges to set up the environment:
   ```bash
   sudo ./configure --user_pass=YOUR_PASSWORD --prefix /desired/installation/path
   ```
   This will:
   - Initialize the MariaDB database and schema
   - Create a new restricted database user (default: `projectlogger`, or custom via `--db_user`)
   - Set the database user's password
   - Copy the CLI executable into the specified prefix path
   - Detect or allow specification of the Python interpreter
   - Install required Python packages (`pip install -r requirements.txt`)
   - Set up correct permissions and configuration files

   You can also:
   - Delete a database user with `--clean`
   - Specify a custom Python interpreter with `--python_path`

3. Ensure the installation path is added to your system's `PATH` if it is not already.

4. The `plogger` command will now be available system-wide.

Example Installation:
```bash
sudo ./configure --user_pass=mypass --prefix /usr/local
```

Custom User Example:
```bash
sudo ./configure --db_user=myuser --user_pass=mypass --prefix=/opt/myapp
```

Delete User Example:
```bash
sudo ./configure --db_user=myuser --clean
```

Custom Python Example:
```bash
sudo ./configure --user_pass=mypass --python_path=/usr/bin/python3.11
```

---

## License

This project is developed for educational purposes as part of the Alfred University CSCI 205 course. Licensing terms may be added later.

---

## Author

Vasilii Maksimov  
Alfred University

---

## Notes

- The application uses a 2-tier architecture with a shared database user restricted to SELECT, INSERT, UPDATE, and DELETE operations.
- No hardcoded users or projects. All records are created via CLI operations.
- Designed for terminal-only use; no GUI components.

---

## Future Enhancements

- Active user tracking (users currently clocked-in)
- Idle project detection (no active users)
- Admin-level database management tools

