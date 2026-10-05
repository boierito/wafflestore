# Isolating intermittent Apple sign-in failures

Build 23009 adds opt-in, volatile evidence collection on an investigation branch;
it is not a claimed fix and not part of the cleaned upstream integration branch.
No extra Apple requests are made when enabling collection. Normal behavior stays
unchanged with collection disabled. Credentials and raw traffic are never exported.

## Capture on a physical, normally signed iPhone

1. Keep the same certificate/bundle ID/machine identity. Note iOS/build, network
   category (Wi-Fi or mobile data), VPN/proxy status and approximate clock accuracy
   separately. Do not publish IP addresses or account identifiers.
2. In Settings, enable Collect sanitized sign-in report. Leave Fresh session OFF.
   Attempt normal sign-in when needed; do not deliberately trigger repeated logout
   or start concurrent clients. If Apple requests 2FA, enter the real code.
3. After a failure, press Sign in once more within five minutes. This is a warm
   trial, with freshly signed requests and the same prepared guest/cookie jar/pod.
   Copy the sanitized report after completion. A successful session stays saved.
4. If failures recur, switch Fresh session ON before the next necessary sign-in.
   This discards the preparation (Bag/guest/pod/ephemeral jar). A new-session
   success does not isolate which of those components caused a difference. Use the same account/network/device and keep
   all other settings unchanged. Challenge cookies remain available for 2FA.
   Do not force a new 2FA code or parallel requests. Stop on rate limits/locked
   account; keep Apple's Retry-After handling intact.
5. Compare several naturally occurring trials, not a burst of synthetic logins.
   Success in one trial is anecdotal; compare HTTP-error counts, automatic/manual
   attempts, Bag/SAP/signing/transfer time and whether success follows a pod change.
6. Only after that, compare Wi-Fi/mobile data as a separate experiment. An
   observation is a lead, not proof of a signature bug or of Apple/network fault.
   Turn collection OFF to clear the report and restore normal warm behavior.

## Fields and interpretation

- trial/preparation IDs and endpoint aliases are local counters, not GUID/DSID.
  Endpoint aliases identify validated public host/path differences; URL queries
  are excluded. Reports contain no URL, Apple ID, password, code, token, cookies,
  SAP exchange, signatures, raw bodies or arbitrary response headers/messages.
- transport-code is a numeric URLError code, not its potentially sensitive
  description. It separates timeouts, lost connections and cancellation from HTTP.
- signature-bytes counts the Base64 header bytes; no signature value is exported.
- signer-ms versus transfer-ms separates local interpretation cost from network
  wait. bag-ms/sap-ms show the setup avoided by a warm trial.
- cookie-jar-count and request-cookie-count describe matching jar entries, not
  wire capture; Foundation can modify automatic headers. No cookie values/names
  or reproducible hashes of credentials/signed bodies are retained.
- request-profile checks the exact body assigned to URLRequest, POST, reference
  Content-Type and User-Agent in memory. signature-valid-base64 checks format
  only. Neither field proves cryptographic validity or Apple acceptance.
- network-protocol/reused-connection/task duration come from public
  URLSessionTaskMetrics for the isolated request. If unavailable before request
  cleanup, collection says unavailable, never borrows a previous request's metrics.
  A reused socket despite separate sessions is a lead for connection isolation.
  No private HTTP-version switch or weakened TLS/certificate validation is used.
- HTTP/body/Apple failure code distinguishes HTML/empty edge responses from
  actual plist credential errors. Numeric codes equal to input secrets are withheld.
- The report accepts only fixed keys and values, keeps at most 240 events in RAM,
  and resets on disabling collection/restarting. A long report can lose earlier
  trials; copy before changing modes. Capture options do not use UserDefaults.

## Reference comparison and next experiments

Reference: majd/ipatool 3411d57f451f5111ae115641c22f7ed17bbd5fbe.
Compare payload fields, exact signed bytes, dynamic Bag endpoints, validated
redirects, cookie scope and independent connection policy. Existing fixtures
verify those client invariants; they cannot verify Apple's acceptance of a failed
signature. If ipatool is available on a computer, compare its outcome sequentially
on the same network/account, respecting rate limits. Its machine identity/TLS
stack differ, so a CLI success does not prove an iOS signing defect.

Use captured evidence to choose the next single-variable change:

| Evidence | Next controlled test |
|---|---|
| Fresh works repeatedly; warm fails | Reduce/disable guest/pod reuse in a test branch, retaining fresh signing and cookies |
| Warm/fresh equivalent; socket reused | Investigate public URLSession isolation options, measure rather than assume |
| Failures tied to one endpoint alias | Re-resolve Bag after bounded rejection, validate route before replay |
| Failures tied to one network | Compare transport timing/HTTP patterns on another network; do not bypass validation |
| Long signer time, normal transfer | Profile TCI hot paths separately, preserve signing semantics |
| Both stacks fail similarly | Wait/check service availability; a backend issue remains a hypothesis |

This build does not hardcode alternate endpoints, invent 2FA codes, add headers
speculatively, increase retry limits or run automated real-account experiments.
A root-cause claim needs repeated device evidence and a regression test/fix.
