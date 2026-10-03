# REST API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Service health |
| POST | `/api/flows` | Validate, analyze, store a synthetic flow |
| GET | `/api/flows` | List flows |
| GET | `/api/flows/{id}` | Retrieve a flow |
| GET | `/api/alerts` | List/filter alerts |
| GET | `/api/alerts/{id}` | Retrieve alert and notes |
| PUT | `/api/alerts/{id}/status` | Update incident status |
| POST | `/api/alerts/{id}/notes` | Add analyst note |
| GET | `/api/dashboard/stats` | SOC summary cards |
| GET | `/api/dashboard/traffic` | Traffic/risk timeline |
| GET | `/api/dashboard/alerts` | Severity/type/protocol/port analytics |
| GET | `/api/rules` | Detection rules |

Production deployment should add authentication, authorization, TLS, rate limiting, audit logging and stronger operational controls.
