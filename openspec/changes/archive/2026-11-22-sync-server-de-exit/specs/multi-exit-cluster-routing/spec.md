## MODIFIED Requirements

### Requirement: Hard isolation guard for `ai-isolated` exit nodes
Each upstream on the bridge SHALL carry a role (`ai-isolated` or `media`). An `ai-isolated` upstream SHALL accept at most one `ai-owner` user, SHALL reject `media-consumer` or second-user bindings, SHALL reject `/24` IPv4 subnet collisions with any `media` upstream (unless explicitly overridden via `--allow-same-subnet`), and SHALL allow shared registrable root domains between `ai-isolated` and `media` upstreams while emitting a non-fatal operational warning.

#### Scenario: Binding a second user or media user to an `ai-isolated` exit is rejected
- **WHEN** an administrator attempts to bind a `media-consumer` user or a second user to an upstream marked `ai-isolated`
- **THEN** the CLI rejects the operation with a non-zero exit code and leaves the bridge state and running Xray configuration unchanged

#### Scenario: Root domain or `/24` subnet collision between `ai-isolated` and `media` upstreams is rejected
- **WHEN** an administrator registers a `media` upstream whose `/24` IPv4 subnet matches an existing `ai-isolated` upstream without `--allow-same-subnet` (or vice versa)
- **THEN** the CLI rejects the registration to prevent subnet-wide quarantine correlation
- **AND WHEN** they share only a registrable root domain on distinct `/24` subnets
- **THEN** the CLI permits the registration and emits a non-fatal `Shared root domain` warning
