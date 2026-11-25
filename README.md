# hhf-forum-automation

Automation for forum.hhf.technology:

- **Docs sync** (`docs-sync.yml`, `src/hhf/docs_import.py`, `config/docs.yml`): imports MDX docs into forum topics.
- **Form sync** (`form-sync.yml`, `src/hhf/form_sync.py`, `forms/`): keeps the onboarding form in sync from `forms/onboarding.yml`.
- **Release feed** (`release-feed.yml`, `src/hhf/release_feed.py`, `config/releases.yml`): see below.

Secrets: `DISCOURSE_URL`, `DISCOURSE_API_KEY` (set with `scripts/set-secrets.sh`).

Where the forum credentials live:

- **`forum-feed` environment** (deployment branch `main`, no required reviewers): used by `release-feed` and `docs-sync`, which run on a schedule or on dispatch.
- **`forum-production` environment** (deployment branch `main`, required reviewers): used by `form-sync`.
- Each environment holds its own `DISCOURSE_URL` and `DISCOURSE_API_KEY`, and the optional variable `DISCOURSE_API_USERNAME`, the forum account the key belongs to. Without that variable the workflows act as `system`. The release feed also reads `WORKFLOW_WEBHOOK_URL_RELEASE` and `WORKFLOW_WEBHOOK_TOKEN` from `forum-feed`.
- Repository-level secrets with the same names still work, because environment jobs can read them, but environment values win. Delete the repository-level copies once both environments are set.
- The API user must be an admin: provisioning creates groups through `/admin/groups.json` and changes the `default_categories_muted` site setting, and form sync edits Discourse Workflows.

The daily briefing and weekly advisory moved to https://github.com/hhftechnology/hhf-blog-automation.

## Release feed

### Forum-managed approval and large imports

The catalogue can generate configuration PRs after staff approval in the forum, including one PR for a reviewed 2,000-app selection. Its dedicated GitHub App verifies the approved contents and successful `validate` checks before merging. Manual configuration PRs remain supported. Owner setup and forum behavior are documented in the catalogue's `docs/release-onboarding.md`.

New channel provisioning runs immediately after configuration merges, then continues every fifteen minutes. Each run handles at most fifty incomplete channels and checks a ten-minute deadline between channels. `state/release_provisioning.json` records partial IDs, activation timestamps and safe error classifications; only completed channels enter `state/release_channels.json`. One failed channel does not prevent other selected channels or existing release polling. Retrying reuses existing resources.

Release polling remains every six hours. It reads all GitHub release pages, distinguishes fetch errors from empty repositories, and persists processed release identities after every successful post. Existing last-tag state migrates on the first successful scan; a missing checkpoint requires repair rather than silently dropping missed versions. Forum release headings reconcile posts that succeeded before state persistence. Newly activated channels baseline history while recovering releases published after activation, including the first future release of an initially empty repository. Raw Git tags and historical backfill remain outside this feed.

To recover a missing legacy checkpoint, inspect the channel's existing forum release headings and GitHub's current published releases before changing `state/releases.json` in a reviewed PR. Never delete the state file to silence an error: that would rebaseline every channel. Correct provisioning exceptions at their source and rerun; do not clear saved IDs.

Validation and recovery tests: `python -m hhf.release_feed --validate-only` and `python -m pytest -q`. These are offline; live GitHub App permissions, forum provisioning and DM delivery need a pilot with owner credentials. Do not assume two thousand categories perform acceptably without measuring the production forum.

### Existing release channel setup

Long polling cycles save a channel cursor in `state/releases.json` and resume on fifteen-minute provisioning runs (`--bootstrap --continue-poll`). The normal cycle still starts every six hours. Rate-limit deferrals keep the release checkpoint unchanged; repository-budget exhaustion resumes at the next unprocessed channel. Deadlines are checked between repositories, so unusually large individual histories require pilot measurements.

Every 6 hours the feed provisions missing release channels, then posts new GitHub releases of the repos in `config/releases.yml` as replies in one pinned, closed topic per repo (parent category "Project Releases" by default). State is `state/releases.json`; channel IDs and discussion bindings are published as a full snapshot in `state/release_channels.json`. The first run only records a baseline.

Each entry may set `parent` (parent category name, default "Project Releases"), `name` (subcategory name, default the repo basename) and `tag_prefix` (only tags starting with it are posted, so one repo can feed several subcategories, e.g. `ios-` / `mac-`, or skip moving tags like `stable`). State is keyed by the repo, or `repo#tag_prefix` when a prefix is set. Group names must be 1-20 characters of `a-z0-9_-`. New child categories give their release group `create_post` permission so members can reply in the separate open discussion topic; everyone remains read-only and the release feed topic is pinned and closed.

Subscribing: releases are muted for everyone by default, so they stay out of Latest. A member joins the repo's public group (for example `releases-traefik`) to get the subcategory on Watching and a DM for every release. To unsubscribe, leave the group (stops the DMs) and set the subcategory's bell back to Normal: Discourse does not reset notification levels when a member leaves a group.

Setup (the API user must be an admin, see above):

1. Add an entry to `config/releases.yml`. New channels need `app_reference` for a catalogue-approved icon or a reviewed HTTPS `icon_url`; `groups` may be omitted, in which case it is generated from the channel name. Explicit group names for new channels must start with `releases-`; completed legacy mappings retain their existing names.
2. Run `python -m hhf.release_feed --bootstrap --dry-run` to review the planned resources. A normal scheduled run provisions missing category, pinned closed release topic, public group with its approved icon, group Watching, and an open discussion topic for newly created channels. It records IDs in `state/release_channels.json`; the workflow commits that mapping for the catalogue to consume. Existing configured channels, groups, members, and topic status are left alone.
3. Generate and import the DM workflow: `python scripts/build_workflow_json.py --out docs/workflows`, then import `docs/workflows/4-release-notify.json`. In its Webhook node attach a Bearer Token credential holding `WORKFLOW_WEBHOOK_TOKEN`; the production URL it shows is `WORKFLOW_WEBHOOK_URL_RELEASE`. Then **Publish** the workflow: an imported workflow is a draft, and its webhook only accepts calls once published. Without it, posts still go out but no DMs are sent.
4. Set the secrets `WORKFLOW_WEBHOOK_URL_RELEASE` and `WORKFLOW_WEBHOOK_TOKEN` (`scripts/set-secrets.sh`). Without them the feed still posts, and only the DMs are skipped. The workflow validates each payload before sending DMs. Its webhook uses `on_received`, so HTTP 200 confirms receipt only; asynchronous validation or delivery failures do not change that response. A webhook failure only warns; the post is already made and the state still advances.

Pull requests run `--validate-only` and the mocked suite without Discourse credentials. Merging a `config/releases.yml` change to `main` starts provisioning immediately; fifteen-minute runs continue pending provisioning and six-hour runs poll releases.
