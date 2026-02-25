# Train-Ticket Graph API

A RESTful query engine over the [Train-Ticket](https://github.com/FudanSELab/train-ticket) microservice
dependency graph, built with **FastAPI** and **Python 3.14**.

---

## Project Structure

```
.
├── org/xyz/backslash/
│   ├── main.py                  # FastAPI app factory + __main__ entry point
│   ├── api/
│   │   ├── dependencies.py      # Dependency injection wiring
│   │   └── routes/
│   │       ├── graph.py         # POST /api/graph/query, GET /api/graph, GET /api/graph/filters
│   │       ├── nodes.py         # GET /api/nodes, GET /api/nodes/{name}
│   │       └── health.py        # GET /health
│   ├── core/
│   │   ├── config.py            # pydantic-settings, APP_* env vars
│   │   └── logging.py           # stdlib logging setup
│   ├── models/
│   │   ├── graph.py             # Domain models: Node, Edge, Vulnerability, GraphData
│   │   └── schemas.py           # API response models, decoupled from domain
│   └── services/
│       ├── graph_repository.py  # GraphLoader ABC, JsonFileLoader, GraphRepository
│       ├── graph_query.py       # Iterative DFS, filter evaluation, result assembly
│       └── filters.py           # Filter ABC, implementations, VulnerabilityParams, FilterParams
├── data/
│   └── train-ticket.json        # Graph data (46 nodes, 98 edges)
├── tests/
│   ├── conftest.py
│   ├── test_repository.py
│   ├── test_filters.py
│   ├── test_query_service.py
│   └── test_requirements.py
├── Dockerfile                   # Multi-stage build, python:3.14-slim
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
| Domain models | `models/graph.py` | `Node`, `Edge`, `Vulnerability`, `GraphData` — pure data, no I/O |
| API schemas | `models/schemas.py` | Response shapes, serialisation aliases, no business logic |
| Repository | `services/graph_repository.py` | `GraphLoader` ABC, `JsonFileLoader`, index structures |
| Query service | `services/graph_query.py` | DFS traversal, filter evaluation, result assembly |
| Filters | `services/filters.py` | `Filter` ABC, concrete implementations, `FilterParams` request model |
| Routes | `api/routes/` | HTTP interface only — no logic, delegate to services |
| DI | `api/dependencies.py` | `get_loader → get_repository → get_query_service` via `Depends` |
| Config | `core/config.py` | Typed settings from environment variables |

---

## Design decisions

### GraphLoader — open/closed data loading

`GraphRepository` accepts any `GraphLoader` implementation and has no knowledge of where data comes from
or what format it is in. `JsonFileLoader` is the built-in implementation for local JSON files. Adding a
new source (YAML, database, HTTP API) means adding a new `GraphLoader` subclass — `GraphRepository`, the
query service, and the routes are unaffected. The test fixtures use an `InMemoryLoader` that serves a
pre-built `GraphData` dict without touching the filesystem.

### Pydantic for data loading

The graph JSON is parsed via `GraphData.model_validate_json()`. Field aliases map JSON names to Python
names (`publicExposed` → `public_exposed`, `from`/`to` → `source`/`target`). A `@model_validator` on
`GraphData` expands edges whose `"to"` value is a list into individual single-target edges before field
parsing. Invalid data — unknown severity values, missing required fields — raises a `ValidationError`
at startup.

### Iterative DFS

`GraphQueryService` enumerates paths using an explicit stack rather than recursion. Each stack frame
holds `(current_node, path_so_far, visited_set)`. Copying path and visited per frame gives each branch
of the traversal an independent state, which is the iterative equivalent of backtracking in recursive
DFS. The goal is exhaustive path enumeration, not shortest-path search, so DFS is the natural fit —
BFS would still have to explore every branch and would carry larger per-frame state.

### `FilterParams` as the complete query model

All query inputs — traversal constraints (`start`, `end`) and path filters (`starts_from_public`,
`ends_at_sink`, `vulnerability`, `node_kind`) — are defined in a single Pydantic model and supplied
together as a POST request body. This gives full Pydantic validation, automatic OpenAPI schema
generation, and a single place to add new inputs. `start` and `end` are fields on `FilterParams`
rather than query parameters; they do not produce filters but are read directly by the query service.

### `VulnerabilityParams` as a nested object

The vulnerability filter has two orthogonal dimensions: whether to include or exclude matching paths
(`exclude: bool`) and which severity level to scope to (`severity: Optional[VulnerabilitySeverity]`).
These are grouped into a nested `VulnerabilityParams` object. Its presence in `FilterParams.vulnerability`
means "apply this filter"; its absence means "don't filter by vulnerability at all". Unknown fields in
the request body are silently ignored (Pydantic's default `extra="ignore"`) to allow new fields to be
deployed server-side without breaking existing clients.

### Domain models vs API schemas

`Node`, `Edge`, and `Vulnerability` in `models/graph.py` carry business logic (`is_sink`,
`has_vulnerability`, `vulnerabilities_by_severity`) and use Python naming conventions. The `*Response`
models in `models/schemas.py` are the external contract — they use JSON naming conventions via field
aliases (`from`/`to`, `publicExposed`) and contain no logic. Serialisation concerns do not leak into
the domain layer.

### Dependency injection and caching

The dependency chain is declared explicitly so FastAPI can wire and override each step independently:

```
get_settings() → get_loader() → get_repository() → get_query_service()
```

`get_loader` and `get_repository` are both decorated with `@lru_cache` for process-level singletons.
`get_loader` always returns the same instance, so `get_repository`'s cache always sees the same key —
plain Python objects are hashable by identity by default — and the repository is constructed exactly
once. `get_query_service` is stateless and cheap, so it is created per-request with no caching needed.

Each level is independently overridable via `app.dependency_overrides` in tests: the loader can be
swapped without touching the repository, and the repository without touching the query service.

---

## Running locally

```bash
# Python 3.14 required

# 1. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements-dev.txt

# 3. Configure (optional)
cp .env.example .env

# 4. Start the server
uvicorn org.xyz.backslash.main:app --reload --port 8080
# or
python -m org.xyz.backslash.main
```

Interactive docs: **http://localhost:8080/docs**

---

## Running with Docker

```bash
docker compose up --build

# or manually
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

Settings are read from environment variables (prefix `APP_`) or a `.env` file.

| Variable | Default | Description |
|---|---|---|
| `APP_LOG_LEVEL` | `info` | Log level |
| `APP_DATA_FILE` | `data/train-ticket.json` | Path to graph JSON |
| `APP_HOST` | `0.0.0.0` | Bind host |
| `APP_PORT` | `8080` | Bind port |

---

## API Reference

### `GET /health`

```json
{"status": "ok"}
```

### `GET /api/graph`

Returns all nodes and direct edges.

### `POST /api/graph/query`

Returns a filtered sub-graph. All inputs are optional and combinable.

**Request body:**

| Field | Type | Description |
|---|---|---|
| `start` | `string` | Constrain traversal to paths originating from this node |
| `end` | `string` | Constrain traversal to paths terminating at this node |
| `starts_from_public` | `bool` | Include only paths whose first node has `publicExposed: true` |
| `ends_at_sink` | `bool` | Include only paths whose last node is a sink (`rds` or `sqs`) |
| `vulnerability` | `VulnerabilityParams` | See below |
| `node_kind` | `string` | Include only paths containing a node of this kind |

**`VulnerabilityParams`:**

| Field | Type | Default | Description |
|---|---|---|---|
| `severity` | `high` \| `medium` \| `low` | `null` | Scope to a specific severity; omit for any |
| `exclude` | `bool` | `false` | `true` → include only paths with no matching vulnerability |

**Response shape:**

```json
{
  "nodes": [...],
  "edges": [{"from": "...", "to": "..."}],
  "meta": {
    "total_paths": 12,
    "active_filters": ["starts_from_public", "has_vulnerability"]
  }
}
```

The response includes all nodes that appear on a matching path, not only those that caused the path
to match. For example, a vulnerability filter returns the vulnerable node and all other nodes on
the same path.

**Examples:**

```json
{"start": "user-service", "end": "prod-postgresdb"}
```
```json
{"starts_from_public": true, "ends_at_sink": true}
```
```json
{"vulnerability": {}}
```
```json
{"vulnerability": {"severity": "high"}}
```
```json
{"vulnerability": {"exclude": true}}
```
```json
{"vulnerability": {"exclude": true, "severity": "high"}}
```
```json
{"starts_from_public": true, "vulnerability": {"severity": "high"}, "node_kind": "rds"}
```

### `GET /api/graph/filters`

Returns documentation for all available query fields.

### `GET /api/nodes`

Returns all nodes.

### `GET /api/nodes/{name}`

Returns a single node by name. `404` if not found.

---

## Adding a new data source

Implement `GraphLoader` and pass it to `GraphRepository`:

```python
class YamlFileLoader(GraphLoader):
    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> GraphData:
        import yaml
        return GraphData.model_validate(yaml.safe_load(self._path.read_text()))

# In dependencies.py or wherever the repo is constructed:
repo = GraphRepository(YamlFileLoader(Path("data/graph.yaml")))
```

Nothing above `GraphRepository` changes.

---

## Extending the filter system

Adding a new filter requires two changes:

```python
# 1. Implement the Filter ABC in services/filters.py
class IsDeprecatedFilter(Filter):
    def accepts(self, path: list[str], repo: GraphRepository) -> bool:
        return any(
            (node := repo.get_node(n)) is not None and node.metadata.get("deprecated")
            for n in path
        )

# 2. Add a field and a branch to FilterParams in the same file
class FilterParams(BaseModel):
    ...
    is_deprecated: bool = False

    def to_filters(self) -> list[Filter]:
        ...
        if self.is_deprecated:
            filters.append(IsDeprecatedFilter())
        return filters
```

The route, query service, OpenAPI docs, and validation update automatically.