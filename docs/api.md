# API assessment

The `api` module is an authorized, scope-enforced API assessment workspace. Target traffic is sent through the project-local `tools/api_request.py` wrapper so configured base URLs, HTTP methods, credentials, rate spacing and redirect behavior remain explicit.

## Create a workspace

After installing the module from the repository README:

```bash
mkdir -p ~/security-work
./toolkit init api ~/security-work/customer-api
cd ~/security-work/customer-api
```

Configure `target/TARGET.toml` before sending requests.

Example:

```toml
[engagement]
name = "API assessment"
authorized = true

[orchestration]
max_parallel_agents = 2

[[scope.rules]]
base_url = "https://api.example.test/v1/"
methods = ["GET", "HEAD", "OPTIONS"]

[limits]
request_spacing_ms = 500
request_timeout_seconds = 20

[[credentials.profiles]]
name = "anonymous"
headers = {}
```

Additional credential profiles can carry project-local headers, for example an explicitly supplied authorization token. Credentials and customer scope stay in the assessment workspace and must not be committed to the toolkit repository.

## Scope enforcement

`target/TARGET.toml` is the project's immutable scope policy during an assessment run. All target traffic must use:

```text
python3 tools/api_request.py
```

The wrapper requires:

- `engagement.authorized=true`;
- the requested URL to start with an allowed `scope.rules[].base_url`;
- the HTTP method to be explicitly allowed by that matching rule;
- the requested credential profile to come from the configured project profiles.

Discovered hosts or paths do not automatically extend scope.

The wrapper intentionally does not follow redirects. A redirect response is recorded with its `Location` header so it can be reviewed against the configured scope before any new request is made.

Configured request spacing and timeouts are applied to each request.

## Manual wrapper use

Check the current authorization/scope count without sending target traffic:

```bash
python3 tools/api_request.py --check
```

Send a scoped request:

```bash
python3 tools/api_request.py GET https://api.example.test/v1/status
```

Use a named credential profile:

```bash
python3 tools/api_request.py GET https://api.example.test/v1/account --profile authenticated
```

Send a request body only when the configured method/scope and engagement authorize it:

```bash
python3 tools/api_request.py POST https://api.example.test/v1/example --profile authenticated --data '{"example":true}'
```

The wrapper stores response bodies and request metadata below:

```text
reports/http/
```

Metadata includes the method, URL, HTTP status, redirect location when present, matched scope rule and credential profile name.

## OpenCode workflow

Start the API assessment orchestrator with:

```bash
./start.sh
```

The module is evidence-led and should prefer low-impact/non-destructive tests. Agents must respect `orchestration.max_parallel_agents` and use the request wrapper for target traffic rather than issuing uncontrolled requests directly.

Important candidate findings require evidence and independent validation. Authorization, authentication, object ownership, input handling and state-changing behavior should be tested only within the configured scope and supplied credentials.

## Workspace updates

Refresh toolkit-managed code/agents in an existing API project without replacing its scope, evidence or reports:

```bash
./toolkit sync api ~/security-work/customer-api
```

Sync preserves `target/TARGET.toml`, `input/`, `work/`, `reports/` and existing findings while refreshing managed module files.
