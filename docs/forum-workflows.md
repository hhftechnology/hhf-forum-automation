# Forum workflows (discourse-workflows)

Three workflows on the forum connect the GitHub Actions jobs (`weekly-advisory.yml`, `daily-briefing.yml`) to
the staff review queue. Property names below were read from the plugin source
(`plugins/discourse-workflows/lib/discourse_workflows/nodes/`), node types and versions included.

Flow: GitHub Action -> `webhook.py` POST -> workflow 1 creates a **draft** topic in a staff-only drafts category,
tags it and PMs staff -> a moderator reviews and moves it into category **86** -> workflow 2 announces it in
News (category **87**). Workflow 3 watches the Actions runs.

## 0. One-time setup

1. Create two staff-only categories, e.g. *Advisory drafts* and *Briefing drafts*. Note their ids
   (`ADVISORY_DRAFTS_CATEGORY_ID`, `BRIEFING_DRAFTS_CATEGORY_ID`; they are only used by `--direct`).
2. Make sure these tags exist or that the bot may create tags: `security, cve, weekly-security, self-hosted,
   daily-briefing, critical, high, medium, low` and the threat-type / industry slugs from `config/taxonomy.yml`.
   Tags the actor is not allowed to create make the **Topic tags** node fail (`unapplied_tag_names`).
3. Admin -> Plugins -> Discourse Workflows -> **Credentials**: create a credential of type **Bearer Token** named
   `hhf-webhook-token` holding the value of the GitHub secret `WORKFLOW_WEBHOOK_TOKEN`
   (`openssl rand -hex 32`). For workflow 3 create another Bearer Token credential with a fine-grained GitHub
   token (Actions: read) only if the repo is private.
4. GitHub repo secrets: `WORKFLOW_WEBHOOK_TOKEN`, `WORKFLOW_WEBHOOK_URL_WEEKLY`, `WORKFLOW_WEBHOOK_URL_DAILY`.
   The webhook URL shown in the Webhook node has the form `https://<forum>/workflows/webhooks/<path>`
   (route `match "/webhooks/*path"` in the plugin). Both URL secrets can point at the same path, because the
   workflow branches on `kind`.

## 1. Drafts: webhook -> if kind -> create topic -> tags -> PM staff

Payload sent by `hhf.webhook` (`Authorization: Bearer <WORKFLOW_WEBHOOK_TOKEN>`):

```json
{"kind": "weekly_advisory", "title": "...", "raw": "...markdown...", "tags": ["security", "cve"],
 "external_id": "weekly-advisory-2026-11-09", "category_hint": "advisory-drafts"}
```

Everything arrives under `$json.body` (the webhook node output is `{body, headers, params, query, method,
webhook_url}`).

| # | Node (type, version) | Name | Configuration |
|---|---|---|---|
| 1 | `trigger:webhook` 1.0 | Webhook | **Path** `hhf-drafts`; **HTTP method** `POST`; **Authentication** `bearer_auth` and pick credential `hhf-webhook-token` (slot `auth`); **Response mode** `on_received`; **Response code** `200` |
| 2 | `condition:if` 1.0 | Is weekly advisory | Combinator `and`; condition: string, `equals`; left `={{ $json.body.kind }}`; right `weekly_advisory` |
| 3 | `action:topic` 2.0 | Create advisory draft | on **true** of node 2. **Operation** `create`; **Title** `={{ $json.body.title }}`; **Raw** `={{ $json.body.raw }}`; **Category** = Advisory drafts; **Actor username** `system` (or the bot account) |
| 4 | `condition:if` 1.0 | Is daily briefing | on **false** of node 2. Same as node 2 with right value `daily_briefing`. Its false branch stays empty, so unknown kinds are ignored |
| 5 | `action:topic` 2.0 | Create briefing draft | on **true** of node 4. Same as node 3 with **Category** = Briefing drafts |
| 6 | `action:topic_tags` 2.0 | Topic tags | Fed by node 3 and node 5. **Mode** `modify`; **Topic id** `={{ $json.topic.id }}`; **Add tag names** `={{ $("Webhook").item.json.body.tags }}` (array or comma list; both are accepted); **Actor username** `system` |
| 7 | `action:send_personal_message` 1.0 | Notify staff | **Recipient group names** `staff`; **Sender username** `system`; **Title** `={{ "Draft ready for review: " + $("Webhook").item.json.body.title }}`; **Raw** a short text with the topic link `/t/{{ $json.topic_id }}` (the Topic tags node outputs `{topic_id, tag_names}`) |

Notes:

- The Topic node has no `external_id` property, so idempotency by `external_id` only exists with
  `--direct` (it calls `get_topic_by_external_id` first). The Action runs once per schedule, so duplicates only
  happen on manual re-runs; delete the stray draft.
- Topic creation runs with the actor's guardian: it needs create permission in the drafts category and tagging
  permission. `skip_workflows: true` is set by the node, so creating the draft does not re-trigger workflows.
- Test: open the Webhook node -> **Listen for test event**, then
  `curl -X POST <test-url> -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d @payload.json`.
  Then **Publish** the workflow and use the production URL.

## 2. Announce: topic moved or published into category 86 -> News (87)

| # | Node | Name | Configuration |
|---|---|---|---|
| 1 | `trigger:topic_category_changed` 1.0 | Topic moved | no parameters; output `topic.*` plus `old_category_id` |
| 2 | `condition:if` 1.0 | Moved into source category | number, `equals`; left `={{ $json.topic.category_id }}`; right `86` |
| 3 | `trigger:topic_published` 1.0 | Topic published | **Category ids** `[86]` (property `category_ids`, optionally `include_subcategories`). Fires when a hidden or draft topic is published |
| 4 | `action:topic` 2.0 | Announce in News | **Operation** `create`; **Title** `={{ "New: " + $json.topic.title }}`; **Raw** `=A new post is available: [{{ $json.topic.title }}]({{ $json.topic.url }})`; **Category** `87`; **Actor** `system` |

Connections: 1 -> 2 (true) -> 4, and 3 -> 4. Both triggers may be used on one canvas; each starts its own path.
`$json.topic.url` is already an absolute URL.

## 3. Monitor: daily 07:00 -> GitHub Actions runs -> PM staff on failure

| # | Node | Name | Configuration |
|---|---|---|---|
| 1 | `trigger:schedule` 1.0 | Daily 07:00 | **Rule** -> add interval: `field` `days`, `daysInterval` `1`, `triggerAtHour` `7`, `triggerAtMinute` `0`. Set the workflow timezone in settings if the forum is not UTC |
| 2 | `action:http_request` 1.0 | Latest weekly-advisory run | **Method** `GET`; **URL** `https://api.github.com/repos/OWNER/hhf-forum-automation/actions/workflows/weekly-advisory.yml/runs?per_page=1`; headers `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`; **Authentication** `none` (public repo) or `bearer_token` with the read-only GitHub credential; **Never error** on |
| 3 | `action:http_request` 1.0 | Latest daily-briefing run | Same with `daily-briefing.yml` |
| 4 | `condition:if` 1.0 | Weekly failed? / Daily failed? | Combinator `or`; three string `equals` conditions on `={{ $json.workflow_runs[0].conclusion }}` with `failure`, `timed_out`, `cancelled` |
| 5 | `action:send_personal_message` 1.0 | PM staff | **Recipient group names** `staff`; **Title** `Automation failed: weekly-advisory`; **Raw** `=The latest run ended with {{ $json.workflow_runs[0].conclusion }}: {{ $json.workflow_runs[0].html_url }}` (on the **true** branch) |

Connect node 1 to both HTTP nodes; each HTTP node feeds its own If and PM. `conclusion` is `null` while a run is
in progress, so running jobs never alert. The http_request node is an outbound call from the forum server; it
follows the plugin's own URL safety rules.

## Importable JSON

The plugin ships templates as files but has no import button. A workflow can be created from the same JSON
through the admin endpoint the editor uses (`POST /admin/plugins/discourse-workflows/workflows.json` with a
`workflow` object containing `name`, `nodes`, `connections`). Generate the files and import them with an
admin API key (scope: global, or the workflows endpoints):

```bash
python scripts/build_workflow_json.py --advisory-category <ID> --briefing-category <ID> --repo OWNER/hhf-forum-automation
for f in docs/workflows/*.json; do
  jq '{workflow: {name, nodes, connections}}' "$f" |
  curl -sS -X POST "$DISCOURSE_URL/admin/plugins/discourse-workflows/workflows.json" \
       -H "Api-Key: $DISCOURSE_API_KEY" -H "Api-Username: system" -H 'Content-Type: application/json' -d @-
done
```

After import: open each workflow, attach the credentials (credential ids are instance-specific, so the JSON
has `credentials: {}`), check the category ids, run the manual test and **Publish**. The JSON was built from the
node property definitions but has not been imported into a live forum from this repository; treat the first import
as a test on staging.

## Review checklist for moderators

- Titles and tags are correct; the prose says whether it was AI-assisted (footer line).
- Facts are cross-checked in the linked advisories. AI text is rejected automatically if it contains a CVE,
  GHSA, version, URL or number that is not in the source facts, but the facts come from third-party feeds.
- Move the topic into category 86 to publish (workflow 2 then announces it).
