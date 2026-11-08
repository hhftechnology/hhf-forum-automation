# hhf-forum-automation

Automation for forum.hhf.technology:

- **Docs sync** (`docs-sync.yml`, `src/hhf/docs_import.py`, `config/docs.yml`): imports MDX docs into forum topics.
- **Form sync** (`form-sync.yml`, `src/hhf/form_sync.py`, `forms/`): keeps the onboarding form in sync from `forms/onboarding.yml`.

Secrets: `DISCOURSE_URL`, `DISCOURSE_API_KEY` (set with `scripts/set-secrets.sh`).

The daily briefing and weekly advisory moved to https://github.com/hhftechnology/hhf-blog-automation.
