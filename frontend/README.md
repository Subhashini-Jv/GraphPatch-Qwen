# GraphPatch frontend

The React + Vite workspace for GraphPatch. Every page reads live data from the GraphPatch backend
(`graphpatch_v2/server.py`); nothing is invented, and pages show an empty state until there is real data.

## Use it (no Node needed)

The zip ships a ready build in `frontend/dist`. From the project root:

```bash
python -m graphpatch_v2.server          # open http://localhost:8000
```

The backend serves this frontend at `/` (the original one-page UI is still at `/classic`).

## Develop it

Needs Node.js 20.19+ or 22.12+.

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to the backend on :8000
npm run build      # writes frontend/dist, which the backend then serves
```

Set `VITE_API_BASE_URL` in a `.env` file to use a backend on another address. Model keys stay on the backend:
set them in the shell before starting the server (see Settings in the app).

## Pages and the API they use

| Page | What it shows | Backend |
|---|---|---|
| Overview | project, finding and repair counts, benchmark verified count, CWE chart | `/api/scans`, `/api/benchmark` |
| Repositories | scan a ZIP, a GitHub URL, pasted code or the bundled sample; project inventory | `/api/scan`, `/api/scan/github`, `/api/scan/code`, `/api/sample` |
| Vulnerability Scanner | taint paths with the 0-100 risk score, path steps, source; SARIF, attack tests, OSV library check | `/api/scan/{id}`, `.../graphpatch.sarif`, `.../attack-tests.zip`, `.../libraries` |
| Taint Graph Explorer | one path as a source → propagation → sink graph, with the method source | `/api/scan/{id}` |
| AI Agent Workspace | start a repair (Planner/Coder/Critic, or the no-model rule fix), live log, iterations, plan | `/api/scan/{id}/fix`, `/api/jobs/{id}` |
| Patch Review | side-by-side diff of original and patched files (Monaco, bundled), unified diff per iteration, patched zip | `/api/scan/{id}/fix`, `.../source`, `.../patched.zip` |
| Validation Center | the checks each patch went through and their evidence; benchmark gates and held-out oracles per CVE | `/api/scan/{id}/fix`, `/api/benchmark` |
| Security Reports | verdict counts and comparison of every approach, CWE and risk charts, exports | `/api/benchmark`, `/api/scans`, `.../report.html` |
| Settings | the backend's model and key status, how to set them, run one benchmark CVE | `/api/status`, `/api/benchmark/run` |

In the web workspace a patch is checked by applying the edits, parsing it (javalang for Java, Tree-sitter for Python and JavaScript) and re-running the taint graph.
Compile (G1) and tests (G2) need the project's build, so they run in the benchmark harness (`run_eval`).
