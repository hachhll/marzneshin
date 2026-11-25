# Spec Delta

## ADDED Requirements

### Requirement: Zero-downtime client profile bundle refresh via SSH CLI
The bridge SSH CLI SHALL support `user refresh [<name> | --all]` to re-render existing users' role-scoped client JSON bundles, `bundle-manifest.json`, and `profile_sha256` metadata in `state.json` without rotating UUIDs, altering upstream bindings, or restarting running Xray/Nginx services.

#### Scenario: Refreshing all users updates `media-selective` bundles without touching UUIDs or Xray
- **WHEN** an administrator runs `user refresh --all` on the Cascade Bridge
- **THEN** every configured user's client bundle is regenerated from the latest profile templates, `bundle-manifest.json` and `profile_sha256` are updated in `state.json`, all user UUIDs and upstream bindings remain unchanged, and running Xray/Nginx containers are not restarted

#### Scenario: Refreshing a single user targets only that user's credential directory
- **WHEN** an administrator runs `user refresh <name>` for an existing bridge user
- **THEN** only `<name>`'s credential bundle and `state.json` metadata are updated while all other users' bundles remain untouched, and a missing `<name>` exits non-zero
