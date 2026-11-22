# Spec Delta

## Purpose

Defines static per-user UUID-to-upstream routing, role-based exit isolation, backward-compatible state management, and Zero-Surface SSH CLI administration for a single domestic Cascade Bridge serving multiple independent German exit nodes.

## ADDED Requirements

### Requirement: Multi-exit static UUID routing on the Cascade Bridge
In `bridge` mode, the proxy engine SHALL support multiple named `vless` Reality outbounds (`XHTTP + xmux` with short minute-scale `hMaxReusableSecs` rotation) behind the single `:443` `vless-reality-vision` inbound and SHALL route each client statically by identity (`user` email) with `domainStrategy: "AsIs"` and zero cross-exit load-balancing or failover.

#### Scenario: Distinct users on the same bridge route to different German exits
- **WHEN** `owner` is bound to `exit-ai` and `alice` is bound to `exit-media-1` on the bridge
- **THEN** the rendered Xray configuration contains both `owner` and `alice` UUIDs in the single `:443` inbound, two distinct `XHTTP + Reality + xmux` outbounds (`proxy-exit-ai` and `proxy-exit-media-1` with bounded `hMaxReusableSecs` such as `"180-300"`), and `routing.rules` mapping `user: ["owner"] -> proxy-exit-ai` and `user: ["alice"] -> proxy-exit-media-1` with `domainStrategy: "AsIs"` and no `freedom` outbound

#### Scenario: Unbound or unknown user cannot fall through to direct egress
- **WHEN** a client connection does not match any configured user UUID or explicit upstream route
- **THEN** the bridge never falls back to a domestic `freedom` outbound and fails closed to `block` or Reality decoy fallback

### Requirement: Hard isolation guard for `ai-isolated` exit nodes
Each upstream on the bridge SHALL carry a role (`ai-isolated` or `media`). An `ai-isolated` upstream SHALL accept at most one `ai-owner` user, SHALL reject `media-consumer` or second-user bindings, and SHALL reject root-domain or `/24` IPv4 subnet collisions with any `media` upstream (unless explicitly overridden for `/24`).

#### Scenario: Binding a second user or media user to an `ai-isolated` exit is rejected
- **WHEN** an administrator attempts to bind a `media-consumer` user or a second user to an upstream marked `ai-isolated`
- **THEN** the CLI rejects the operation with a non-zero exit code and leaves the bridge state and running Xray configuration unchanged

#### Scenario: Root domain or `/24` subnet collision between `ai-isolated` and `media` upstreams is rejected
- **WHEN** an administrator registers a `media` upstream whose registrable root domain or `/24` IPv4 subnet matches an existing `ai-isolated` upstream (or vice versa)
- **THEN** the CLI rejects the registration to prevent cross-contour SNI or subnet-wide quarantine correlation

### Requirement: Zero-Surface SSH CLI lifecycle for upstreams and users
The bridge SHALL provide SSH CLI commands (`upstream add/list/remove/migrate` and `user add/list/show/assign/remove`) that manage named upstreams and per-user UUID bindings atomically without any web panel, HTTP API, or subscription endpoint. Reassigning a user or migrating all users from one `media` upstream to another SHALL update only the bridge routing configuration while preserving each user's existing UUID and client profile untouched.

#### Scenario: Zero-client-reconfiguration migration between media exits
- **WHEN** an administrator runs `upstream migrate exit-media-1 exit-media-2`
- **THEN** every user previously bound to `exit-media-1` is rebound to `exit-media-2` in `state.json`, Xray is atomically reloaded, and each user's UUID and client JSON profile remain unchanged

#### Scenario: Deleting an in-use upstream is prevented
- **WHEN** an administrator attempts to run `upstream remove exit-media-1` while one or more users are still bound to `exit-media-1`
- **THEN** the CLI refuses deletion and lists the bound users that must be migrated or removed first

#### Scenario: Revoking a single misbehaving user does not disrupt other users
- **WHEN** an administrator runs `user remove <name>`
- **THEN** only that user's UUID and routing rule are removed from Xray and their credential directory is deleted, while all other users' UUIDs and active bindings remain intact

### Requirement: Backward-compatible v1-to-v2 bridge state migration
Upgrading an existing single-upstream v1 bridge `state.json` (containing flat `upstream_*` fields and a single `user_uuid`) to the multi-exit v2 schema SHALL preserve the existing `user_uuid`, bridge Reality keypair, `shortId`, `bridge_sni`, and existing upstream parameters automatically without disconnecting or requiring re-import on already-configured devices.

#### Scenario: Legacy v1 bridge state upgrades seamlessly to v2
- **WHEN** the v2 CLI loads an existing v1 bridge `state.json`
- **THEN** the existing upstream is migrated into `upstreams` and the existing `user_uuid` is migrated into `users` with the exact same UUID and Reality keys preserved
