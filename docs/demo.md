# Safe demo workflow

1. Generate the 5,000-record dataset.
2. Start the backend.
3. Start the frontend.
4. Open Swagger at `http://127.0.0.1:8000/docs`.
5. Use `POST /api/flows` with a normal HTTPS record.
6. Confirm the response includes risk, classification and matched rules.
7. Submit a synthetic high-connection/failure record.
8. Open the dashboard and observe the alert.
9. Copy the returned alert ID.
10. Open Investigation and enter the ID.
11. Set status to `INVESTIGATING`.
12. Add an analyst note.
13. Resolve as `RESOLVED` or `FALSE_POSITIVE`.

All records remain synthetic; no packet is transmitted.
