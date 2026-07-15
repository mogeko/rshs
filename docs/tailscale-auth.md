# Tailscale Identity Auth

Instead of (or in addition to) Basic Auth, rshs can trust identity headers
that [`tailscale serve`][ts-serve] injects automatically — no shared
passwords, access tied directly to who's logged into the tailnet.

## How `tailscale serve` identity headers work

When `tailscale serve` proxies a request to a local port, and the request
comes from a **user-owned device** on your tailnet (not a [tagged
device][ts-tags] like a server or CI runner), it adds these headers before
forwarding:

| Header                        | Value                                             |
| ------------------------------ | -------------------------------------------------- |
| `Tailscale-User-Login`         | The requester's login, e.g. `alice@example.com`   |
| `Tailscale-User-Name`          | Display name, e.g. `Alice Architect`              |
| `Tailscale-User-Profile-Pic`   | Profile picture URL, if the identity provider has one |

Two properties make this safe to trust as an auth signal:

1. **Only `tailscale serve` sets it.** If an incoming request already has a
   `Tailscale-User-Login` header (or the other identity headers) attached by
   the client, `tailscale serve` strips it before adding its own copy. A
   client cannot forge these headers by just sending them.
2. **It's a proxy header, not a network guarantee.** This means rshs *must*
   only be reachable through `tailscale serve` — if you bind rshs to
   `0.0.0.0` and someone reaches it directly (bypassing `serve`), there's no
   header at all and, depending on your config, that's either a hard 403 or
   (if you haven't set the flag below) unauthenticated access. **Always bind
   rshs to `127.0.0.1`** when using this feature, so the only path in is
   through `tailscale serve`.

Tagged devices (servers, CI, anything with `tailscale up --advertise-tags`)
never get these headers, even when they hit an endpoint proxied by `serve` —
there's no human identity to attach. Plan your allow-list accordingly: a
homelab box reaching a `tailscale serve`d rshs instance will always be
rejected under this auth mode, by design.

See Tailscale's own docs: [Serve][ts-serve] · [Tailscale identity][ts-identity] · [Tags][ts-tags].

[ts-serve]: https://tailscale.com/kb/1312/serve
[ts-identity]: https://tailscale.com/kb/1312/serve#identity-headers
[ts-tags]: https://tailscale.com/kb/1068/acl-tags

## Enabling it

```sh
# Bind to loopback only — tailscale serve is the only path in
rshs -H 127.0.0.1 -p 8765 --accept-tailscale-serve-auth all ./data

# Then, separately, point tailscale serve at that port:
tailscale serve --bg --https=8443 http://127.0.0.1:8765
```

`--accept-tailscale-serve-auth all` accepts **any** authenticated tailnet
user (still requires the header to be present — so tagged devices and
direct access are still rejected). This is the loosest useful setting: "my
tailnet, no passwords."

## Restricting to specific users

```sh
# Single user
rshs --accept-tailscale-serve-auth devuser@example.com ./data

# Multiple users, comma-separated, no spaces required
rshs --accept-tailscale-serve-auth "devuser@example.com,teammate@example.com" ./data

# Via environment variable
RSHS_ACCEPT_TAILSCALE_SERVE_AUTH="devuser@example.com,teammate@example.com" rshs ./data
```

Any login not in the list gets `403 Forbidden`, same as a missing header.

## File-based user mapping

For larger lists, or when you want to attribute logins to a local name
(useful in logs, or a future feature that scopes access per-mapped-name),
use a users file instead of the CLI flag:

```sh
# tailscale-users file
# lines are: LOGIN [MAPPED_NAME]
# blank lines and #-comments are ignored
devuser@example.com admin
teammate@example.com
# alice@example.com  <- commented out, not allowed
```

```sh
rshs --tailscale-users-file ./tailscale-users ./data

# Or via env var
RSHS_TAILSCALE_USERS_FILE=./tailscale-users rshs ./data
```

A bare `all` line anywhere in the file (instead of a login) makes the whole
file behave like `--accept-tailscale-serve-auth all`.

If you pass **both** `--accept-tailscale-serve-auth` and
`--tailscale-users-file`, they're merged — a login is allowed if it appears
in either source, and `all` in either source makes the whole thing `all`.

## Combining with Basic Auth

The two auth mechanisms are independent and both run if configured. This is
mostly useful during a migration: run both while you move clients over to
identity-only access. There's no way to make one auth path replace the
other automatically — each is a separate all-or-nothing gate you configure
explicitly.

## Verifying it's working

```sh
# From your Mac/laptop over the tailnet — should just work, no prompt:
open https://your-server.your-tailnet.ts.net:8443/

# From a tagged device / server — must be rejected:
curl -i https://your-server.your-tailnet.ts.net:8443/
# → 403 Forbidden: no Tailscale identity header on this request
```

If a browser mount is prompting for credentials instead of passing straight
through, double check:

- rshs is bound to `127.0.0.1`, not `0.0.0.0` (otherwise you might be
  hitting it directly, bypassing `tailscale serve`)
- `tailscale serve status` shows the proxy pointed at rshs's port
- You're testing from a user-owned device, not a tagged one
