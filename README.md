# hhf-forum-automation

Automation for forum.hhf.technology:

- **Docs sync** (`docs-sync.yml`, `src/hhf/docs_import.py`, `config/docs.yml`): imports MDX docs into forum topics.
- **Form sync** (`form-sync.yml`, `src/hhf/form_sync.py`, `forms/`): keeps the onboarding form in sync from `forms/onboarding.yml`.
- **Release feed** (`release-feed.yml`, `src/hhf/release_feed.py`, `config/releases.yml`): see below.

Secrets: `DISCOURSE_URL`, `DISCOURSE_API_KEY` (set with `scripts/set-secrets.sh`).

The daily briefing and weekly advisory moved to https://github.com/hhftechnology/hhf-blog-automation.

## Release feed

Every 6 hours the feed posts new GitHub releases of the repos in `config/releases.yml` as replies in one pinned, closed topic per repo (parent category "Project Releases" by default). State is `state/releases.json`; the first run only records a baseline.

Each entry may set `parent` (parent category name, default "Project Releases"), `name` (subcategory name, default the repo basename) and `tag_prefix` (only tags starting with it are posted, so one repo can feed several subcategories, e.g. `ios-` / `mac-`, or skip moving tags like `stable`). State is keyed by the repo, or `repo#tag_prefix` when a prefix is set. Group names must be 1-20 characters of `a-z0-9_-`.

Subscribing: releases are muted for everyone by default, so they stay out of Latest. A member joins the repo's public group (for example `releases-traefik`) to get the subcategory on Watching and a DM for every release. To unsubscribe, leave the group (stops the DMs) and set the subcategory's bell back to Normal: Discourse does not reset notification levels when a member leaves a group.

Setup (the API user must be staff):

1. Add an entry to `config/releases.yml` with `groups: [releases-<repo>]`.
2. `python -m hhf.release_feed --bootstrap --dry-run`, then without `--dry-run` (or run the Release feed workflow with `bootstrap` on, which uses the repo secrets). It creates the category, subcategory, topic and group, sets Watching for the group, mutes the categories by default, and prints `category_id` / `topic_id` to paste into the config.
3. Generate and import the DM workflow: `python scripts/build_workflow_json.py --out docs/workflows`, then import `docs/workflows/4-release-notify.json`. In its Webhook node attach a Bearer Token credential holding `WORKFLOW_WEBHOOK_TOKEN`; the production URL it shows is `WORKFLOW_WEBHOOK_URL_RELEASE`. Then **Publish** the workflow: an imported workflow is a draft, and its webhook only accepts calls once published. Without it, posts still go out but no DMs are sent.
4. Set the secrets `WORKFLOW_WEBHOOK_URL_RELEASE` and `WORKFLOW_WEBHOOK_TOKEN` (`scripts/set-secrets.sh`). Without them the feed still posts, and only the DMs are skipped. A webhook failure only warns; the post is already made and the state still advances.
