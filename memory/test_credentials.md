# Test Credentials

## Admin
- username: `admin`
- password: `admin123`

## Notes
- Login is rate-limited 5/minute - wait between back-to-back logins
- Login sets HttpOnly cookie `access_token` and returns Bearer token
- Test users created via `/api/admin/users` should be prefixed with `TEST_` and deleted via `/admin/users/{id}/complete`
