# Signup protection (AI agents and spam accounts)

Live on forum.hhf.technology since 2026-11-28. Two parts:

1. **Watch list for suspicious new accounts**, adapted from per1234's workflows
   on meta.discourse.org ("AI agents signing up for accounts", topic 414624,
   posts 65-67, CC0-1.0).
2. **Signup honeytrap**: decoy fields on the signup form. Tripping one sends
   the new account into moderation.

## Pieces on the forum

| Piece | Where | What it does |
| --- | --- | --- |
| Group `monitor` | Admin, Groups | Accounts under watch. Visible to staff only. |
| User field `Signup check` (`user_field_8`) | Admin, User fields | Hidden carrier for the honeytrap signals. Optional, not editable, not on profile. |
| Theme component `HHF signup honeytrap` | Admin, Themes (child of "forum 2027") | Source: [`themes/signup-honeytrap`](../../../themes/signup-honeytrap). Adds the decoys and fills `Signup check`. |
| Workflow variables `monitor_group_id`, `maintainer` | Workflows, Variables | Group id of `monitor`; username that gets error PMs. |
| W22a Monitor group button | Workflow | Staff post-menu button: add or remove the post author from `monitor` (locks or unlocks trust level 0). |
| W22b Flag posts from reviewable users | Workflow | On every post or edit by a TL0/TL1 user: scores the account and flags the post when it looks like a throwaway. Posts by `monitor` members are flagged "review and hide". |
| W22c Tidy monitor group | Workflow | Daily: removes permanently suspended accounts from `monitor`. |
| W23 Signup honeytrap | Workflow | Two minutes after signup: reads `Signup check` and acts (below). |

## Honeytrap signals

The theme component writes `v1|a=0|b=0|wd=0|tamper=0|ms=…|keys=…|ptr=…|paste=…`.

| Signal | Meaning | Result |
| --- | --- | --- |
| `a=1` | Filled decoy A, which is off screen and hidden from screen readers | Trap |
| `b=1` | Filled decoy B, which asks AI agents to type AGENT and tells people to leave it empty | Trap |
| `wd=1` | `navigator.webdriver` was true (browser automation) | Trap |
| `tamper=1` or a value without `v1\|` | Something other than the page wrote the hidden field | Trap |
| empty | The page script did not run (API or scripted signup, script blocked) | Weak |
| `ms` under 5 s | Form finished implausibly fast | Weak |
| `keys=0` and `ptr=0` | No real keyboard or pointer input at all | Weak |

- **Trap**: added to `monitor`, trust level locked at 0, user flagged into the
  review queue with the reasons. W22b then hides each of their posts until a
  moderator approves it.
- **Weak**: user flagged for review only; nothing is restricted.
- Staff and staged users are skipped.

To clear a false positive, use the W22a post-menu button on one of their posts
(or remove them from `monitor` and unlock their trust level), then approve the
hidden posts.

## Changes from the meta originals

- The profile-location versus IP check used Discourse AI's classify node.
  Discourse AI is disabled here, so it is off (`profileLocationMismatch: false`).
- Fixed `suspiciousContent()`: `includes(...) != null` was always true, so every
  post counted as suspicious.
- Null guards for missing locations, bio, website and email.
- No 10-minute wait before classifying (there is no AI spam scan to wait for).
- `monitor` members get `review_hide` flags instead of `review`.
- The "lock posts" option was removed: it called workflow id 40, which is an
  unrelated workflow on this forum.

## Rebuilding the JSON

The JSON files here are what was imported. They were generated from the meta
exports by a one-off script; edit them directly from now on, or edit the
workflow in the forum and export it back here.
