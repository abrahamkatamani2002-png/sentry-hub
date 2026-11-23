"""Role names and where each role lands after signing in."""

ADMIN = "admin"
STAFF = "staff"
USER = "user"
ROLES = (ADMIN, STAFF, USER)
ASSIGNABLE = (STAFF, USER)  # roles an admin can hand out from the dashboard


def home_endpoint(role):
    return {ADMIN: "dash.admin", STAFF: "dash.staff"}.get(role, "dash.overview")
