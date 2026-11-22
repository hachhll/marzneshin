# Delta Spec: Media-Selective Routing

## ADDED Requirements

### Requirement: Yazio Routing in Media-Selective Profiles
The `media-selective` profile generator MUST route all Yazio traffic through the `proxy` outbound and `dns-remote` resolver.

#### Scenario: iOS media-selective routes Yazio by domain suffix
- **WHEN** `ios-media-selective.json` is generated for a `media-consumer` user
- **THEN** `yazio.com` is included in `domain_suffix` rules for both `dns-remote` and `proxy` outbound

#### Scenario: Android media-selective routes Yazio by domain and package
- **WHEN** `android-media-selective.json` is generated for a `media-consumer` user
- **THEN** `yazio.com` is included in `domain_suffix` rules and `com.yazio.android` is included in `package_name` rules

### Requirement: Complete TikTok and ByteDance Domain Coverage on iOS
The `media-selective` profile generator MUST include all TikTok and ByteDance regional/CDN domains in `MEDIA_SELECTIVE_DOMAINS` so iOS clients (which cannot use `package_name`) do not leak TikTok traffic to `direct`.

#### Scenario: iOS media-selective includes extended TikTok/ByteDance domains
- **WHEN** `ios-media-selective.json` is generated
- **THEN** `tiktokv.eu`, `tiktokv.us`, `bytegecko.com`, `bytedance.com`, `byteimg.com`, `snssdk.com`, `isnssdk.com`, `sgsnssdk.com`, `amemv.com`, and `pstatp.com` are present in `domain_suffix` rules for `dns-remote` and `proxy`
