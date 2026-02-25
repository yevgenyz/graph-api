# Train-Ticket Graph API

A RESTful query engine over the [Train-Ticket](https://github.com/FudanSELab/train-ticket) microservice dependency graph, built with **FastAPI** and **Python 3.14**.

---

## Project Structure

```
.
├── org/xyz/backslash/           # Root package (org.xyz.backslash)
│   ├── main.py                  # FastAPI app factory (create_app)
│   ├── api/
│   │   ├── dependencies.py      # Dependency injection (repo, query service)
│   │   └── routes/
│   │       ├── graph.py         # GET /api/graph, /api/graph/query, /api/graph/filters
│   │       ├── nodes.py         # GET /api/nodes, /api/nodes/{name}
│   │       └── health.py        # GET /health
│   ├── core/
│   │   ├── config.py            # pydantic-settings (env-driven configuration)
│   │   └── logging.py           # Logging setup
│   ├── models/
│   │   ├── graph.py             # Domain models: Node, Edge, Vulnerability
│   │   └── schemas.py           # API response schemas
│   └── services/
│       ├── graph_repository.py  # Data loading and indexed access
│       ├── graph_query.py       # DFS path-finding and filtered queries
│       └── filters.py           # Filter abstractions + registry
├── data/
│   └── train-ticket.json        # Graph data
├── tests/
│   ├── conftest.py              # Shared pytest fixtures
│   ├── test_repository.py
│   ├── test_filters.py
│   └── test_query_service.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt
└── pytest.ini
```

---

## Architecture

### Layer separation

| Layer | Module | Responsibility |
|---|---|---|
| Domain models | `models/graph.py` | `Node`, `Edge`, `Vulnerability` — pure data, no I/O |
| API schemas | `models/schemas.py` | Request/response shapes, decoupled from domain |
| Repository | `services/graph_repository.py` | Load JSON, indexed node lookup, adjacency map |
| Query service | `services/graph_query.py` | DFS traversal, filter evaluation, result assembly |
| Filters | `services/filters.py` | Abstract `Filter` base + concrete implementations + registry |
| Routes | `api/routes/` | One file per resource, thin — delegate to services |
| DI | `api/dependencies.py` | FastAPI `Depends` wiring (repo → query service) |
| Config | `core/config.py` | `pydantic-settings` — env vars + `.env` file |

### Filter system

Filters are composable and open to extension without modification:

```python
class MyNewFilter(Filter):
    @property
    def name(self) -> str:
        return "my_filter"

    def accepts(self, path: list[str], repo: GraphRepository) -> bool:
        ...  # your logic here

# Register it in filters.py:
FILTER_REGISTRY["my_filter"] = lambda val: MyNewFilter(val)
```

That's all — the route, query service, and tests need no changes.

---

## Running locally

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements-dev.txt

# 3. (Optional) configure via .env
cp .env.example .env

# 4. Start the server
uvicorn org.xyz.backslash.main:app --reload --port 8080
```

Interactive API docs: **http://localhost:8080/docs**

---

## Running with Docker

```bash
# Build and start
docker compose up --build

# Or build and run manually
docker build -t train-ticket-api .
docker run -p 8080:8080 train-ticket-api
```

---

## Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

---

## Configuration

All settings are driven by environment variables (prefix `APP_`) or a `.env` file.

| Variable | Default | Description |
|---|---|---|
| `APP_LOG_LEVEL` | `info` | Uvicorn / stdlib log level |
| `APP_DATA_FILE` | `data/train-ticket.json` | Path to the graph JSON |
| `APP_HOST` | `0.0.0.0` | Bind host |
| `APP_PORT` | `8080` | Bind port |

---

## API Reference

### `GET /health`
Liveness check.

### `GET /api/graph`
Full graph — all nodes and direct edges.

### `GET /api/graph/query`
Filtered sub-graph. All parameters optional and combinable.

| Parameter | Values | Description |
|---|---|---|
| `start` | node name | Paths starting from this node |
| `end` | node name | Paths ending at this node |
| `starts_from_public` | `true` | First node must be publicly exposed |
| `ends_at_sink` | `true` | Last node must be a sink (rds/sqs) |
| `has_vulnerability` | `true` / `high` / `medium` / `low` | Path contains a vulnerable node |
| `node_kind` | `service` / `rds` / `sqs` | Path contains a node of this kind |

**Examples:**
```
GET /api/graph/query?starts_from_public=true&ends_at_sink=true
GET /api/graph/query?has_vulnerability=high
GET /api/graph/query?start=user-service&end=prod-postgresdb
```

### `GET /api/graph/filters`
Self-documenting list of available filter parameters.

### `GET /api/nodes`
All nodes.

### `GET /api/nodes/{name}`
Single node by name. Returns 404 if not found.
