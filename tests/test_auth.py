import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from src import app as api
from src import manage_users


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.student_hash = api.hash_password("student-password")
        cls.admin_hash = api.hash_password("admin-password")

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.account_file = Path(self.temp_dir.name) / "users.json"
        self.account_file.write_text(
            json.dumps(
                [
                    {
                        "username": "student",
                        "email": "student@mergington.edu",
                        "role": "student",
                        "password_hash": self.student_hash,
                    },
                    {
                        "username": "admin",
                        "email": "admin@mergington.edu",
                        "role": "admin",
                        "password_hash": self.admin_hash,
                    },
                ]
            ),
            encoding="utf-8",
        )
        self.account_file_patch = patch.object(api, "AUTH_USERS_FILE", self.account_file)
        self.account_file_patch.start()
        self.original_activities = copy.deepcopy(api.activities)
        api.sessions.clear()
        self.client = TestClient(api.app)

    def tearDown(self):
        self.client.close()
        api.activities.clear()
        api.activities.update(self.original_activities)
        api.sessions.clear()
        self.account_file_patch.stop()
        self.temp_dir.cleanup()

    def test_anonymous_users_cannot_change_rosters(self):
        signup = self.client.post(
            "/activities/Chess Club/signup",
            params={"email": "new-student@mergington.edu"},
        )
        unregister = self.client.delete(
            "/activities/Chess Club/unregister",
            params={"email": "michael@mergington.edu"},
        )

        self.assertEqual(signup.status_code, 401)
        self.assertEqual(unregister.status_code, 401)
        activity = self.client.get("/activities").json()["Chess Club"]
        self.assertEqual(activity["participant_count"], 2)
        self.assertEqual(activity["participants"], [])

    def test_students_can_view_but_not_manage_participants(self):
        login = self.client.post(
            "/auth/login", json={"username": "student", "password": "student-password"}
        )
        self.assertEqual(login.status_code, 200)
        self.assertNotIn("password_hash", login.json()["user"])

        activity = self.client.get("/activities").json()["Chess Club"]
        self.assertEqual(activity["participants"], [])
        self.assertEqual(activity["participant_count"], 2)
        response = self.client.post(
            "/activities/Chess Club/signup",
            params={"email": "new-student@mergington.edu"},
        )
        self.assertEqual(response.status_code, 403)

    def test_admin_can_view_and_manage_rosters(self):
        login = self.client.post(
            "/auth/login", json={"username": "admin", "password": "admin-password"}
        )
        self.assertEqual(login.status_code, 200)
        self.assertIn("httponly", login.headers["set-cookie"].lower())

        activity = self.client.get("/activities").json()["Chess Club"]
        self.assertIn("michael@mergington.edu", activity["participants"])
        signup = self.client.post(
            "/activities/Chess Club/signup",
            params={"email": "new-student@mergington.edu"},
        )
        self.assertEqual(signup.status_code, 200)
        self.assertIn("by admin", signup.json()["message"])

        unregister = self.client.delete(
            "/activities/Chess Club/unregister",
            params={"email": "new-student@mergington.edu"},
        )
        self.assertEqual(unregister.status_code, 200)

    def test_invalid_password_and_logout(self):
        invalid_login = self.client.post(
            "/auth/login", json={"username": "admin", "password": "wrong-password"}
        )
        self.assertEqual(invalid_login.status_code, 401)

        self.client.post(
            "/auth/login", json={"username": "admin", "password": "admin-password"}
        )
        logout = self.client.post("/auth/logout")
        self.assertEqual(logout.status_code, 200)
        self.assertIsNone(self.client.get("/auth/me").json()["user"])

    def test_account_command_persists_a_password_hash(self):
        with (
            patch.object(manage_users, "AUTH_USERS_FILE", self.account_file),
            patch.object(
                sys,
                "argv",
                [
                    "manage_users.py",
                    "new-admin",
                    "new-admin@mergington.edu",
                    "--role",
                    "admin",
                ],
            ),
            patch.object(
                manage_users.getpass,
                "getpass",
                side_effect=["long-enough-password", "long-enough-password"],
            ),
        ):
            manage_users.main()

        created_account = json.loads(self.account_file.read_text(encoding="utf-8"))[-1]
        self.assertNotEqual(created_account["password_hash"], "long-enough-password")
        self.assertTrue(
            api.verify_password("long-enough-password", created_account["password_hash"])
        )


if __name__ == "__main__":
    unittest.main()
