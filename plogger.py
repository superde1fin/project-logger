import argparse
import secrets
import bcrypt
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import os
import getpass
from datetime import datetime, timedelta

SESSION_FILE = os.path.expanduser('~/.projectlog_session')

def check_logged_in():
    if not os.path.exists(SESSION_FILE):
        return None  # No session file = not logged in

    try:
        with open(SESSION_FILE, 'r') as f:
            content = f.read().strip()
            user_id, session_token = content.split()

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id, username, role FROM People WHERE id = %s AND session_token = %s", (user_id, session_token))
        user = cursor.fetchone()

        if user:
            return user  # User is logged in and session is valid
        else:
            return None  # Session invalid (e.g., token mismatch)

    except Exception as e:
        print(f"Error checking login status: {e}")
        return None

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def load_db_config():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    dotenv_path = os.path.join(script_dir, "config", ".env")
    load_dotenv(dotenv_path = dotenv_path)

    db_config = {
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASS"),
        "database": os.getenv("DB_NAME"),
        "host": os.getenv("DB_HOST", "localhost")  # Default to localhost if not set
    }

    return db_config

def get_db_connection():
    conf_dict = load_db_config()
    try:
        connection = mysql.connector.connect(
            host=conf_dict["host"],
            user=conf_dict["user"],
            password=conf_dict["password"],
            database=conf_dict["database"]
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Database connection error: {e}")
        exit(1)

def signup_handler(args):

    user = check_logged_in()
    if user:
        print(f"You are logged in as {user['username']}.\nPlease log out before creating a new user")
        return

    username = args.username
    name = " ".join(args.name)
    role = args.role.lower()
    password = getpass.getpass(prompt="Enter your password: ")
    password2 = getpass.getpass(prompt="Repeat password: ")

    if password != password2:
        print("Passwords don't match. Please try again")
        return

    print(f"Signing up {username} as {role}")

    if role not in ["user", "advisor"]:
        print("Invalid role. Must be user or advisor.")
        return

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if username already exists
        cursor.execute("SELECT id FROM People WHERE username = %s", (username,))
        if cursor.fetchone():
            print(f"Username {username} already exists. Please choose a different username.")
            return

        # Insert new user
        insert_query = """
            INSERT INTO People (username, name, role, password_hash)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(insert_query, (username, name, role, hashed_password))
        conn.commit()

        print(f"User {username} successfully signed up as a/an {role}.")

    except Error as e:
        print(f"Error during signup: {e}")
    finally:
        cursor.close()
        conn.close()

    login_handler(args, from_signup = True)

def login_handler(args, from_signup = False):
    username = args.username
    if not from_signup:
        user = check_logged_in()
        if user:
            print(f"You are already logged in as {user['username']}")
            return

        password = getpass.getpass(prompt="Enter your password: ")
        print(f"Logging in {username}")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # dictionary=True allows access by column names

    try:
        # 1. Fetch user's password hash
        cursor.execute("SELECT id, password_hash FROM People WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            print(f"Username {username} not found.")
            return

        if not from_signup:
            stored_hash = user['password_hash'].encode('utf-8')

            # 2. Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                print("Incorrect password.")
                return

        # 3. Generate a secure session token
        session_token = secrets.token_hex(32)  # 64-character secure token

        # 4. Update session_token in database
        cursor.execute("UPDATE People SET session_token = %s WHERE id = %s", (session_token, user['id']))
        conn.commit()

        # 5. Write the session token and user ID to a local file
        with open(SESSION_FILE, 'w') as f:
            f.write(f"{user['id']} {session_token}\n")

        # 6. Set local file permissions to 600 (private)
        os.chmod(SESSION_FILE, 0o600)

        print(f"User {username} logged in successfully")


    except Error as e:
        print(f"Database error during login: {e}")

    finally:
        cursor.close()
        conn.close()

def logout_handler(args):
    try:
        # 1. Check that user is logged in
        user = check_logged_in()

        if not user:
            print("You are not logged in")
            return

        # 2. Connect to database
        conn = get_db_connection()
        cursor = conn.cursor()

        # 3. Clear the session_token field
        cursor.execute("UPDATE People SET session_token = NULL WHERE id = %s", (user["id"], ))
        conn.commit()

        # 4. Delete the session file
        os.remove(SESSION_FILE)

        print("Logout successful. Session cleared.")

    except Exception as e:
        print(f"Error during logout: {e}")

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def delete_user_handler(args):
    try:
        #1. Check if logged in
        user = check_logged_in()
        if not user:
            print("You are not logged in.")
            return

        # 2. Connect to DB
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT password_hash FROM People WHERE id = %s", (user["id"],))
        
        # 3. Make sure that password hash exists
        result = cursor.fetchone()
        if not result:
            print("Invalid session. Please log in again.")
            return

        hashed_pass = result["password_hash"]

        # 4. Prompt for password again
        password_attempt = getpass.getpass(prompt="Enter your password to confirm account deletion: ")

        stored_hash = hashed_pass.encode('utf-8')

        # 5. Verify password
        if not bcrypt.checkpw(password_attempt.encode('utf-8'), stored_hash):
            print("Password incorrect. Account deletion cancelled.")
            return

        # 6. Delete user from People table
        cursor.execute("DELETE FROM People WHERE id = %s", (user["id"],))
        conn.commit()

        # 7. Delete session file
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)

        print(f"Account {user['username']} successfully deleted.")

    except Exception as e:
        print(f"Error during account deletion: {e}")

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def add_project_handler(args):
    user = check_logged_in()
    if not user:
        print("You must be logged in as an advisor to add a project.")
        return

    if user['role'] != 'advisor':
        print("Permission denied. Only advisors can add projects.")
        return

    project_name = args.name
    week_hour_goal = args.goal

    if week_hour_goal <= 0:
        print("Weekly hour goal must be positive.")
        return

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        insert_project_query = """
            INSERT INTO Projects (project_name, week_hour_goal)
            VALUES (%s, %s)
        """
        cursor.execute(insert_project_query, (project_name, week_hour_goal))

        project_id = cursor.lastrowid

        # Insert into Assigned — assign advisor as supervisor
        insert_assigned_query = """
            INSERT INTO Assigned (person_id, project_id, is_supervisor)
            VALUES (%s, %s, TRUE)
        """

        cursor.execute(insert_assigned_query, (user['id'], project_id))

        conn.commit()

        print(f"Project {project_name} created successfully with ID {project_id}. You are now the supervisor.")

    except Exception as e:
        print(f"Error creating project: {e}")

    finally:
        cursor.close()
        conn.close()

def delete_project_handler(args):
    user = check_logged_in()
    if not user:
        print("You must be logged in as an advisor to delete a project.")
        return

    if user['role'] != 'advisor':
        print("Permission denied. Only advisors can delete projects.")
        return

    project_id = args.id

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. Check if project exists
        cursor.execute("SELECT project_name FROM Projects WHERE id = %s", (project_id,))
        project = cursor.fetchone()

        if not project:
            print(f"Project with ID {project_id} does not exist.")
            return

        # 2. Fetch advisor's password hash
        cursor.execute("SELECT password_hash FROM People WHERE id = %s", (user["id"],))
        result = cursor.fetchone()

        if not result:
            print("Error verifying advisor identity. Please log in again.")
            return

        hashed_password = result["password_hash"].encode('utf-8')

        # 3. Prompt for password
        print(f"ALL INFORMATION REGARDING {project['project_name']} WILL BE PERMANENTLY DELETED")
        password_attempt = getpass.getpass(prompt="Enter your password to confirm project deletion: ")

        if not bcrypt.checkpw(password_attempt.encode('utf-8'), hashed_password):
            print("Password incorrect. Project deletion cancelled.")
            return

        # 4. Proceed to delete
        cursor.execute("DELETE FROM Assigned WHERE project_id = %s", (project_id,))
        cursor.execute("DELETE FROM Log WHERE project_id = %s", (project_id,))
        cursor.execute("DELETE FROM Projects WHERE id = %s", (project_id,))
        conn.commit()

        print(f"Project '{project['project_name']}' (ID {project_id}) successfully deleted.")

    except Exception as e:
        print(f"Error during project deletion: {e}")

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def view_projects_handler(args):
    user = check_logged_in()
    if not user:
        print("You must be logged in to view projects.")
        return

    supervisor_filter = args.supervisor
    sort_by = args.sort  # 'id' or 'name'

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        if supervisor_filter:
            if supervisor_filter.lower() == "me":
                query = """
                    SELECT DISTINCT p.id, p.project_name, p.week_hour_goal
                    FROM Projects p
                    JOIN Assigned a ON p.id = a.project_id
                    WHERE a.person_id = %s
                """
                params = (user['id'],)
            else:
                try:
                    supervisor_id = int(supervisor_filter)
                except ValueError:
                    print("Supervisor ID must be an integer or 'me'.")
                    return

                cursor.execute("SELECT role FROM People WHERE id = %s", (supervisor_id,))
                result = cursor.fetchone()
                if not result:
                    print(f"User with ID {supervisor_id} does not exist.")
                    return
                if result["role"] != "advisor":
                    print(f"User with ID {supervisor_id} is not an advisor.")
                    return

                query = """
                    SELECT DISTINCT p.id, p.project_name, p.week_hour_goal
                    FROM Projects p
                    JOIN Assigned a ON p.id = a.project_id
                    WHERE a.person_id = %s AND a.is_supervisor = TRUE
                """
                params = (supervisor_id,)
        else:
            query = "SELECT id, project_name, week_hour_goal FROM Projects"
            params = ()

        # Add sorting
        if sort_by == 'name':
            query += " ORDER BY project_name ASC"
        else:
            query += " ORDER BY id ASC"

        cursor.execute(query, params)
        projects = cursor.fetchall()

        if not projects:
            print("No projects found.")
            return

        # Display the projects
        print(f"{'ID':<5} {'Project Name':<30} {'Weekly Hour Goal':<20}")
        print("-" * 60)
        for proj in projects:
            print(f"{proj['id']:<5} {proj['project_name']:<30} {proj['week_hour_goal']:<20.2f}")

    except Exception as e:
        print(f"Error retrieving projects: {e}")

    finally:
        cursor.close()
        conn.close()



def assign_user_handler(args):
    user = check_logged_in()
    if not user:
        print("You must be logged in as an advisor to assign users.")
        return

    if user['role'] != 'advisor':
        print("Permission denied. Only advisors can assign users to projects.")
        return

    project_id = args.project_id
    username_to_assign = args.username
    make_supervisor = args.supervisor  # True/False

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. Check if advisor supervises this project
        cursor.execute("""
            SELECT 1 FROM Assigned
            WHERE person_id = %s AND project_id = %s AND is_supervisor = TRUE
        """, (user['id'], project_id))
        supervision = cursor.fetchone()

        if not supervision:
            print(f"You are not a supervisor for project ID {project_id}. Cannot assign users to it.")
            return

        # 2. Check if user exists
        cursor.execute("SELECT id FROM People WHERE username = %s", (username_to_assign,))
        person = cursor.fetchone()

        if not person:
            print(f"User '{username_to_assign}' does not exist.")
            return

        person_id = person["id"]

        # 3. Check if user already assigned
        cursor.execute("""
            SELECT 1 FROM Assigned
            WHERE person_id = %s AND project_id = %s
        """, (person_id, project_id))
        existing = cursor.fetchone()

        if existing:
            print(f"User '{username_to_assign}' is already assigned to project ID {project_id}.")
            return

        # 4. Insert into Assigned
        cursor.execute("""
            INSERT INTO Assigned (person_id, project_id, is_supervisor)
            VALUES (%s, %s, %s)
        """, (person_id, project_id, make_supervisor))

        conn.commit()

        role_msg = "as supervisor" if make_supervisor else "as regular contributor"
        print(f"User '{username_to_assign}' successfully assigned to project ID {project_id} {role_msg}.")

    except Exception as e:
        print(f"Error assigning user: {e}")

    finally:
        cursor.close()
        conn.close()

def remove_user_handler(args):
    user = check_logged_in()
    if not user:
        print("You must be logged in as an advisor to remove users.")
        return

    if user['role'] != 'advisor':
        print("Permission denied. Only advisors can remove users from projects.")
        return

    project_id = args.project_id
    username_to_remove = args.username

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. Check if advisor supervises this project
        cursor.execute("""
            SELECT 1 FROM Assigned
            WHERE person_id = %s AND project_id = %s AND is_supervisor = TRUE
        """, (user['id'], project_id))
        supervision = cursor.fetchone()

        if not supervision:
            print(f"You are not a supervisor for project ID {project_id}. Cannot remove users from it.")
            return

        # 2. Check if user exists
        cursor.execute("SELECT id FROM People WHERE username = %s", (username_to_remove,))
        person = cursor.fetchone()

        if not person:
            print(f"User '{username_to_remove}' does not exist.")
            return

        person_id = person["id"]

        # 3. Check if user is assigned to the project
        cursor.execute("""
            SELECT 1 FROM Assigned
            WHERE person_id = %s AND project_id = %s
        """, (person_id, project_id))
        assignment = cursor.fetchone()

        if not assignment:
            print(f"User '{username_to_remove}' is not assigned to project ID {project_id}.")
            return

        # 4. Remove the user
        cursor.execute("""
            DELETE FROM Assigned
            WHERE person_id = %s AND project_id = %s
        """, (person_id, project_id))
        conn.commit()

        print(f"User '{username_to_remove}' successfully removed from project ID {project_id}.")

    except Exception as e:
        print(f"Error removing user: {e}")

    finally:
        cursor.close()
        conn.close()

def view_team_handler(args):
    user = check_logged_in()
    if not user:
        print("You must be logged in as an advisor to view team members.")
        return

    if user['role'] != 'advisor':
        print("Permission denied. Only advisors can view team members.")
        return

    project_id = args.project_id

    if args.days:
        start_time = datetime.now() - timedelta(days=args.days)
        header_timeframe = f"last {args.days} days"
    else:
        # Default to start of current calendar week
        today = datetime.now()
        start_time = today - timedelta(days=today.weekday())
        start_time = start_time.replace(hour=0, minute=0, second=0, microsecond=0)
        header_timeframe = "this week"

    print(f"Team members for project ID {project_id} ({header_timeframe}):")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. Check if advisor supervises this project
        cursor.execute("""
            SELECT 1 FROM Assigned
            WHERE person_id = %s AND project_id = %s AND is_supervisor = TRUE
        """, (user['id'], project_id))
        supervision = cursor.fetchone()

        if not supervision:
            print(f"You are not a supervisor for project ID {project_id}. Cannot view team members.")
            return

        # 2. Get list of assigned users
        cursor.execute("""
            SELECT p.id, p.username, p.name, a.is_supervisor
            FROM Assigned a
            JOIN People p ON a.person_id = p.id
            WHERE a.project_id = %s
            ORDER BY a.is_supervisor DESC, p.username ASC
        """, (project_id,))
        team = cursor.fetchall()

        if not team:
            print(f"No users assigned to project ID {project_id}.")
            return

        # 3. For each user, get total worked time during the timeframe
        print(f"Team members for project ID {project_id} (last {days} days):")
        print(f"{'Username':<20} {'Full Name':<30} {'Role':<15} {'Total Time':<10}")
        print("-" * 85)

        for member in team:
            member_id = member['id']
            cursor.execute("""
                SELECT clock_in_time, clock_out_time
                FROM Log
                WHERE person_id = %s AND project_id = %s AND clock_in_time >= %s
            """, (member_id, project_id, start_time))
            logs = cursor.fetchall()

            total_seconds = 0
            for log in logs:
                clock_in = log["clock_in_time"]
                clock_out = log["clock_out_time"]

                if clock_out:
                    total_seconds += (clock_out - clock_in).total_seconds()

            hours = int(total_seconds // 3600)
            minutes = int((total_seconds % 3600) // 60)
            total_time_str = f"{hours:02}:{minutes:02}"

            role = "Supervisor" if member['is_supervisor'] else "Contributor"
            print(f"{member['username']:<20} {member['name']:<30} {role:<15} {total_time_str:<10}")

    except Exception as e:
        print(f"Error viewing team: {e}")

    finally:
        cursor.close()
        conn.close()

def clock_in_handler(args):
    user = check_logged_in()
    if not user:
        print("You must be logged in to clock into a project.")
        return

    project_id = args.project_id

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. Check if user is assigned to project
        cursor.execute("""
            SELECT 1 FROM Assigned
            WHERE person_id = %s AND project_id = %s
        """, (user['id'], project_id))
        assignment = cursor.fetchone()

        if not assignment:
            print(f"You are not assigned to project ID {project_id}. Cannot clock in.")
            return

        # 2. Check if already clocked in (open session exists)
        cursor.execute("""
            SELECT 1 FROM Log
            WHERE person_id = %s AND project_id = %s AND clock_out_time IS NULL
        """, (user['id'], project_id))
        open_session = cursor.fetchone()

        if open_session:
            print(f"You are already clocked into project ID {project_id}. Please clock out before clocking in again.")
            return

        # 3. Insert new clock-in entry
        cursor.execute("""
            INSERT INTO Log (person_id, project_id, clock_in_time)
            VALUES (%s, %s, %s)
        """, (user['id'], project_id, datetime.now()))
        conn.commit()

        print(f"Successfully clocked into project ID {project_id} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")

    except Exception as e:
        print(f"Error during clock-in: {e}")

    finally:
        cursor.close()
        conn.close()

def clock_out_handler(args):
    user = check_logged_in()
    if not user:
        print("You must be logged in to clock out of a project.")
        return

    project_id = args.project_id

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. Check if there is an open clock-in session
        cursor.execute("""
            SELECT id, clock_in_time FROM Log
            WHERE person_id = %s AND project_id = %s AND clock_out_time IS NULL
        """, (user['id'], project_id))
        open_session = cursor.fetchone()

        if not open_session:
            print(f"No active clock-in session found for project ID {project_id}. Please clock in first.")
            return

        log_id = open_session["id"]

        # 2. Update the clock_out_time
        cursor.execute("""
            UPDATE Log
            SET clock_out_time = %s
            WHERE id = %s
        """, (datetime.now(), log_id))
        conn.commit()

        clock_in_time = open_session['clock_in_time']
        print(f"Successfully clocked out of project ID {project_id}. You were clocked in since {clock_in_time.strftime('%Y-%m-%d %H:%M:%S')}.")

    except Exception as e:
        print(f"Error during clock-out: {e}")

    finally:
        cursor.close()
        conn.close()



def view_logs_handler(args):
    user = check_logged_in()
    if not user:
        print("You must be logged in to view your logs.")
        return

    if args.days:
        start_time = datetime.now() - timedelta(days=args.days)
        header_timeframe = f"last {args.days} days"
    else:
        # Default to start of current calendar week
        today = datetime.now()
        start_time = today - timedelta(days=today.weekday())
        start_time = start_time.replace(hour=0, minute=0, second=0, microsecond=0)
        header_timeframe = "this week"

    print(f"Team members for project ID {project_id} ({header_timeframe}):")

    project_id = args.project_id


    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        query = """
            SELECT p.project_name, l.clock_in_time, l.clock_out_time
            FROM Log l
            JOIN Projects p ON l.project_id = p.id
            WHERE l.person_id = %s AND l.clock_in_time >= %s
        """
        params = [user['id'], start_time]

        if project_id:
            query += " AND l.project_id = %s"
            params.append(project_id)

        query += " ORDER BY l.clock_in_time ASC"

        cursor.execute(query, tuple(params))
        logs = cursor.fetchall()

        if not logs:
            print("No log entries found for the specified period.")
            return

        print(f"Log entries for user '{user['username']}' in the past {days} days:")
        print(f"{'Project':<30} {'Clock In':<20} {'Clock Out':<20} {'Duration':<10}")
        print("-" * 90)

        total_seconds = 0

        for log in logs:
            project_name = log["project_name"]
            clock_in = log["clock_in_time"]
            clock_out = log["clock_out_time"]

            if not clock_out:
                duration = "Open session"
            else:
                duration_td = clock_out - clock_in
                seconds = duration_td.total_seconds()
                total_seconds += seconds
                hours = int(seconds // 3600)
                minutes = int((seconds % 3600) // 60)
                duration = f"{hours:02}:{minutes:02}"

            clock_in_str = clock_in.strftime("%Y-%m-%d %H:%M")
            clock_out_str = clock_out.strftime("%Y-%m-%d %H:%M") if clock_out else "In Progress"

            print(f"{project_name:<30} {clock_in_str:<20} {clock_out_str:<20} {duration:<10}")

        if project_id:
            total_hours = int(total_seconds // 3600)
            total_minutes = int((total_seconds % 3600) // 60)
            print("-" * 90)
            print(f"Total time spent on project ID {project_id}: {total_hours}h {total_minutes}m")

    except Exception as e:
        print(f"Error retrieving logs: {e}")

    finally:
        cursor.close()
        conn.close()

def check_goal_handler(args):
    user = check_logged_in()
    if not user:
        print("You must be logged in as an advisor to check project goals.")
        return

    if user['role'] != 'advisor':
        print("Permission denied. Only advisors can check project goals.")
        return

    project_id = args.project_id
    today = datetime.now()
    start_time = today - timedelta(days=today.weekday())
    start_time = start_time.replace(hour=0, minute=0, second=0, microsecond=0)

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. Check if advisor supervises the project
        cursor.execute("""
            SELECT p.project_name, p.week_hour_goal
            FROM Projects p
            JOIN Assigned a ON p.id = a.project_id
            WHERE p.id = %s AND a.person_id = %s AND a.is_supervisor = TRUE
        """, (project_id, user['id']))
        project = cursor.fetchone()

        if not project:
            print(f"You are not supervising project ID {project_id}, or it does not exist.")
            return

        project_name = project["project_name"]
        goal_hours = project["week_hour_goal"]

        # 2. Calculate total logged time
        cursor.execute("""
            SELECT clock_in_time, clock_out_time
            FROM Log
            WHERE project_id = %s AND clock_in_time >= %s
        """, (project_id, start_time))
        logs = cursor.fetchall()

        total_seconds = 0
        for log in logs:
            clock_in = log["clock_in_time"]
            clock_out = log["clock_out_time"]
            if clock_out:
                total_seconds += (clock_out - clock_in).total_seconds()

        actual_hours = total_seconds / 3600

        # 3. Compare actual vs goal
        diff_hours = goal_hours - actual_hours

        print(f"Project '{project_name}' (ID {project_id}) Goal Check (last 7 days):")
        print("-" * 50)
        print(f"Weekly Hour Goal: {goal_hours:.2f} hours")
        print(f"Actual Logged:    {actual_hours:.2f} hours")

        if diff_hours > 0:
            print(f"Remaining to goal: {diff_hours:.2f} hours")
        else:
            print(f"Goal exceeded by: {abs(diff_hours):.2f} hours!")

    except Exception as e:
        print(f"Error checking goal: {e}")

    finally:
        cursor.close()
        conn.close()





def main():
    parser = argparse.ArgumentParser(description="Project Logger CLI")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Signup
    signup_parser = subparsers.add_parser("signup", help="Create a new user or advisor account")
    signup_parser.add_argument("-u", "--username", required=True, help="Desired username")
    signup_parser.add_argument("-n", "--name", required=True, nargs = "+", help="Full name")
    signup_parser.add_argument("-r", "--role", required=True, choices=["user", "advisor"], help="Role in system")
    signup_parser.set_defaults(func=signup_handler)

    # Login
    login_parser = subparsers.add_parser("login", help="Login with existing credentials")
    login_parser.add_argument("-u", "--username", required=True, help="Your username")
    login_parser.set_defaults(func=login_handler)

    # Logout
    logout_parser = subparsers.add_parser('logout', help='Logout and clear session')
    logout_parser.set_defaults(func=logout_handler)

    # Delete user
    delete_user_parser = subparsers.add_parser('delete-user', help='Permanently delete a user')
    delete_user_parser.set_defaults(func=delete_user_handler)

    # Add project
    add_project_parser = subparsers.add_parser('add-project', help='Create a new project (advisor only)')
    add_project_parser.add_argument('-n', '--name', required=True, help='Name of the project')
    add_project_parser.add_argument('-g', '--goal', required=True, type=float, help='Weekly hour goal for the project')
    add_project_parser.set_defaults(func=add_project_handler)

    # Delete project
    delete_project_parser = subparsers.add_parser('delete-project', help='Delete an existing project (advisor only)')
    delete_project_parser.add_argument('-i', '--id', required=True, type=int, help='ID of the project to delete')
    delete_project_parser.set_defaults(func=delete_project_handler)

    # View projects
    view_projects_parser = subparsers.add_parser('view-projects', help='View all projects or filter by supervisor')
    view_projects_parser.add_argument('-s', '--supervisor', required=False, help="Filter projects by supervisor id of use 'me' to show projects assign to current username")
    view_projects_parser.add_argument('--sort', required=False, choices=['id', 'name'], default='id', help="Sort projects by 'id' (default) or 'name'")
    view_projects_parser.set_defaults(func=view_projects_handler)

    # Assign user
    assign_user_parser = subparsers.add_parser('assign-user', help='Assign a user to a project (advisor only)')
    assign_user_parser.add_argument('-i', '--project-id', required=True, type=int, help='Project ID')
    assign_user_parser.add_argument('-u', '--username', required=True, help='Username to assign')
    assign_user_parser.add_argument('--supervisor', action='store_true', help='Assign user as supervisor (optional)')
    assign_user_parser.set_defaults(func=assign_user_handler)

    # Remove user
    remove_user_parser = subparsers.add_parser('remove-user', help='Remove a user from a project (advisor only)')
    remove_user_parser.add_argument('-i', '--project-id', required=True, type=int, help='Project ID')
    remove_user_parser.add_argument('-u', '--username', required=True, help='Username to remove')
    remove_user_parser.set_defaults(func=remove_user_handler)

    # View team
    view_team_parser = subparsers.add_parser('view-team', help='View assigned users for a project (advisor only)')
    view_team_parser.add_argument('-i', '--project-id', required=True, type=int, help='Project ID')
    view_team_parser.add_argument('-d', '--days', required=False, type=int, help='Number of past days to include (default current week)')
    view_team_parser.set_defaults(func=view_team_handler)


    # Clock-in
    clock_in_parser = subparsers.add_parser('clock-in', help='Clock into a project')
    clock_in_parser.add_argument('-i', '--project-id', required=True, type=int, help='Project ID to clock into')
    clock_in_parser.set_defaults(func=clock_in_handler)

    # Clock-out
    clock_out_parser = subparsers.add_parser('clock-out', help='Clock out of a project')
    clock_out_parser.add_argument('-i', '--project-id', required=True, type=int, help='Project ID to clock out from')
    clock_out_parser.set_defaults(func=clock_out_handler)

    # View personal logs
    view_logs_parser = subparsers.add_parser('view-logs', help='View your time logs')
    view_logs_parser.add_argument('-d', '--days', required=False, type=int, help='Show logs for past N days (default current week)')
    view_logs_parser.add_argument('-i', '--project-id', required=False, type=int, help='Filter by project ID')
    view_logs_parser.set_defaults(func=view_logs_handler)

    # Check project goal
    check_goal_parser = subparsers.add_parser('check-goal', help='Check if a project met its weekly hour goal (advisor only)')
    check_goal_parser.add_argument('-i', '--project-id', required=True, type=int, help='Project ID to check')
    check_goal_parser.set_defaults(func=check_goal_handler)



    # Parse args and call appropriate handler
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

