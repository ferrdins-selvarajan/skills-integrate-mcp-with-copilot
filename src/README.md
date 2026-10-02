# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Sign in with a student or administrator account
- Allow administrators to manage activity rosters
- Keep participant email addresses visible only to administrators

## Getting Started

1. Install the dependencies:

   ```
   pip install -r requirements.txt
   ```

2. Run the application:

   ```
   uvicorn src.app:app --reload
   ```

3. Create accounts. Passwords are prompted interactively and stored as salted PBKDF2 hashes:

   ```
   python src/manage_users.py coordinator coordinator@mergington.edu --role admin
   python src/manage_users.py student student@mergington.edu --role student
   ```

   The account file defaults to `src/users.json` and is excluded from version control. Set `AUTH_USERS_FILE` to use a different path. For HTTPS deployments, set `SECURE_COOKIES=true`.

4. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/auth/login`                                                      | Sign in and create an HTTP-only session cookie                      |
| GET    | `/auth/me`                                                         | Get the current signed-in account                                   |
| POST   | `/auth/logout`                                                     | Sign out and revoke the current session                             |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Administrator-only roster signup                                   |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Administrator-only roster removal                                |

The activity list is public, but participant email addresses are returned only to administrators. Student accounts can view activities and counts; only administrators can view or change rosters. Sessions are held in memory and expire after eight hours, so restarting the server signs everyone out.

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
