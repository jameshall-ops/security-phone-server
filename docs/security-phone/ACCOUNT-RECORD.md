# Security Phone account record

WO-SP-13 defines the durable account and device metadata retained by the Security Phone server. Message content,
message-store metadata and push-provider processing are outside this document.

## Privacy rules

- A device user agent is never stored in the account record. Legacy `userAgent` properties are accepted only so an
  existing account can be read, discarded during deserialization and omitted on the next account write.
- `lastSeen` is the start of a seven-day privacy bucket, not the time of the request. A stable offset derived from the
  account identifier distributes bucket boundaries across the week. A device record can advance at most once in any
  seven-day interval for that account.
- User agents received on individual requests may still be processed transiently for compatibility or coarse
  operational metrics. They are not copied into `Account` or `Device`.
- Push tokens remain because push delivery is an explicit Security Phone requirement. Clearing a token removes its
  platform signal; the server does not retain a replacement platform label.

## Account fields

| Stored property | Purpose | Retention rule |
| --- | --- | --- |
| `uuid` | Stable account identifier (ACI). | Account lifetime. |
| `pni` | Optional phone-number identity identifier retained for upstream protocol compatibility. | Until number removal or account deletion. Security Phone registration does not collect E.164 data. |
| `number` | Optional legacy/upstream number field. | Absent for governed Security Phone registrations; otherwise until number removal or account deletion. |
| `usernameHash` | Resolves the current username without storing plaintext. | Until username change/removal or account deletion. |
| `reservedUsernameHash` | Protects an in-progress username reservation. | Until reservation completion/expiry. |
| `usernameLinkHandle` | Resolves an active username link. | Until link rotation/removal or account deletion. |
| `eu` | Encrypted username-link payload. | Same as `usernameLinkHandle`. |
| `devices` | Contains the governed device records listed below. | Per device until unlink or account deletion. |
| `identityKey` | ACI public identity key needed for end-to-end encryption. | Account lifetime or governed key replacement. |
| `pniIdentityKey` | Optional PNI public identity key for protocol compatibility. | Same as `pni`. |
| `cpv` | Current profile version used for conditional profile updates. | Until replaced or account deletion. |
| `badges` | Upstream schema-compatibility records. Consumer badge features are disabled by WO-SP-10. | Until expiry/removal or account deletion. |
| `registrationLock`, `registrationLockSalt` | Salted registration-lock verifier. | Until reset/removal or account deletion. |
| `uak` | Unidentified-access key for sealed-sender authorization. | Until rotation/removal or account deletion. |
| `uua` | Whether sealed sender is allowed without the access key. | Until preference change or account deletion. |
| `inCds` | Optional directory-discoverability preference. | Until preference change or account deletion. |
| `bcr`, `mbcr` | Backup and media-backup credential requests. | Until replacement/removal or account deletion. |
| `bv` | Backup voucher receipt level and expiry. | Until expiry/replacement or account deletion. |
| `zck`, `zckr` | Backup zero-knowledge credential key and rotation identifier. | Until governed rotation or account deletion. |
| `version` | Optimistic-lock version preventing lost writes. | Account lifetime. |
| `holds` | Username hashes held through explicit expiry timestamps. | Until each hold expires or is removed. |
| `arps`, `arph` | Salt and hash for the account recovery password. | Until rotation/removal or account deletion. |
| `acs` | Salt for account-authentication credentials. | Until rotation or account deletion. |
| `pendingTotp` | Pending TOTP enrollment material. | Until enrollment completes, is cancelled or expires. |
| `mfa` | Active governed MFA keys and their identifiers. | Until key removal/rotation or account deletion. |

## Device fields

| Stored property | Purpose | Retention rule |
| --- | --- | --- |
| `id` | Account-local device identifier. | Device lifetime. |
| `name` | Client-encrypted device name. | Until renamed/unlinked. |
| `createdAt` | Encrypted creation timestamp used by device APIs. | Device lifetime. |
| `authToken`, `salt` | Salted device-authentication verifier. | Until credential rotation/unlink. |
| `gcmId`, `apnId` | Android or Apple push-delivery token. | Until token replacement, clear or unlink. |
| `pushTimestamp` | Time the active push token was last replaced. | While a push token is retained. |
| `fetchesMessages` | Whether the client retrieves messages directly. | Until delivery-mode change or unlink. |
| `registrationId`, `pniRegistrationId` | Protocol registration identifiers for ACI and optional PNI key delivery. | Device lifetime or key re-registration. |
| `lastSeen` | Start of the account-offset seven-day activity bucket. | Replaced no more than once per seven-day bucket; removed on unlink. |
| `created` | Device creation time used for lifecycle and device-management decisions. | Device lifetime. |
| `capabilities` | Protocol capabilities required for safe feature negotiation. | Until capability update or unlink. |

`userAgent` is intentionally absent from this table and from the current serialized schema.

## Migration behavior

No destructive bulk rewrite is required. The server reads a legacy device record containing `userAgent`, ignores that
property, and writes the current schema without it on the next account mutation. New and reclaimed devices start with
the current weekly `lastSeen` bucket. Authenticated activity advances the stored bucket only when the account-specific
seven-day boundary has passed.

## Human gate

- Privacy Owner: pending
- Decision: deferred
- Approval date: pending

