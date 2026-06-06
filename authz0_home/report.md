# authz0 scan report

- **targets:** 6
- **probes:** 24
- **findings:** 6 (6 unauthorized, 0 over-restrictive)
- **errors:** 0

| #  | Status | Method | Target                            | Role       | Access | Expected | Verdict |
|----|--------|--------|-----------------------------------|------------|--------|----------|---------|
| #0 | 200    | GET    | http://127.0.0.1:8810/account     | admin      | yes    | yes      | O       |
| #0 | 200    | GET    | http://127.0.0.1:8810/account     | user       | yes    | yes      | O       |
| #0 | 200    | GET    | http://127.0.0.1:8810/account     | guest      | yes    | yes      | O       |
| #0 | 200    | GET    | http://127.0.0.1:8810/account     | admin_test | yes    | yes      | O       |
| #1 | 200    | GET    | http://127.0.0.1:8810/admin       | admin      | yes    | yes      | O       |
| #1 | 403    | GET    | http://127.0.0.1:8810/admin       | user       | no     | no       | O       |
| #1 | 403    | GET    | http://127.0.0.1:8810/admin       | guest      | no     | no       | O       |
| #1 | 200    | GET    | http://127.0.0.1:8810/admin       | admin_test | yes    | no       | X       |
| #2 | 200    | GET    | http://127.0.0.1:8810/admin/users | admin      | yes    | yes      | O       |
| #2 | 403    | GET    | http://127.0.0.1:8810/admin/users | user       | no     | no       | O       |
| #2 | 403    | GET    | http://127.0.0.1:8810/admin/users | guest      | no     | no       | O       |
| #2 | 200    | GET    | http://127.0.0.1:8810/admin/users | admin_test | yes    | no       | X       |
| #3 | 200    | GET    | http://127.0.0.1:8810/orders/1    | admin      | yes    | yes      | O       |
| #3 | 200    | GET    | http://127.0.0.1:8810/orders/1    | user       | yes    | no       | X       |
| #3 | 200    | GET    | http://127.0.0.1:8810/orders/1    | guest      | yes    | no       | X       |
| #3 | 200    | GET    | http://127.0.0.1:8810/orders/1    | admin_test | yes    | no       | X       |
| #4 | 200    | GET    | http://127.0.0.1:8810/reports     | admin      | yes    | yes      | O       |
| #4 | 200    | GET    | http://127.0.0.1:8810/reports     | user       | yes    | yes      | O       |
| #4 | 200    | GET    | http://127.0.0.1:8810/reports     | guest      | no     | no       | O       |
| #4 | 200    | GET    | http://127.0.0.1:8810/reports     | admin_test | yes    | no       | X       |
| #5 | 200    | GET    | http://127.0.0.1:8810/admin       | admin      | yes    | yes      | O       |
| #5 | 403    | GET    | http://127.0.0.1:8810/admin       | user       | no     | no       | O       |
| #5 | 403    | GET    | http://127.0.0.1:8810/admin       | guest      | no     | no       | O       |
| #5 | 200    | GET    | http://127.0.0.1:8810/admin       | admin_test | yes    | yes      | O       |

## Findings

- **[unauthorized]** `GET http://127.0.0.1:8810/admin` as **admin\_test** — unauthorized access: role 'admin\_test' reached a resource it should not
- **[unauthorized]** `GET http://127.0.0.1:8810/admin/users` as **admin\_test** — unauthorized access: role 'admin\_test' reached a resource it should not
- **[unauthorized]** `GET http://127.0.0.1:8810/orders/1` as **user** — unauthorized access: role 'user' reached a resource it should not
- **[unauthorized]** `GET http://127.0.0.1:8810/orders/1` as **guest** — unauthorized access: role 'guest' reached a resource it should not
- **[unauthorized]** `GET http://127.0.0.1:8810/orders/1` as **admin\_test** — unauthorized access: role 'admin\_test' reached a resource it should not
- **[unauthorized]** `GET http://127.0.0.1:8810/reports` as **admin\_test** — unauthorized access: role 'admin\_test' reached a resource it should not
