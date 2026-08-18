# Challenge corpus strategy

Auto-Shark must not be judged only on the five private captures used for the
acceptance gate. Those captures are regression anchors, not a representative
training set. New samples should be added by behavior and protocol family,
with the capture SHA-256, source URL, license/redistribution status, and a
short human solution record kept outside production detectors.

## Coverage matrix

The next corpus expansion should cover at least:

- cleartext TCP/Telnet credentials, fragmented and retransmitted payloads;
- HTTP keep-alive and HTTP/2-to-HTTP/1 gateways, redirects, chunked bodies,
  multipart uploads, cookies, and nested URL/Base64/hex encodings;
- SQL injection: boolean, UNION, error, time-delay, JSON, and encoded inputs,
  including negative controls with normal search parameters;
- WebShell families beyond PHP `eval`: uploaders, command wrappers, ASP/JSP,
  and encrypted or compressed request bodies;
- extracted files: JPEG/PNG trailing data, ZIP/RAR/7z, PDFs, office files,
  DNS/ICMP tunnels, FTP/TFTP transfers, and archive-password workflows;
- malformed captures, missing reassembly fields, connection reuse, and large
  bodies that exercise every byte/count budget.

## Source policy

Public captures can be used for local validation only until their license and
redistribution terms are recorded. The existing public SQL teaching capture is
machine-local for this reason. Private challenge captures and answer files
remain outside Git; answers are test oracles only and are never passed to an
analyzer. A corpus entry should look like:

```text
name | protocol/behavior | source | sha256 | license | local_path | status
```

The first additional real-world validation is recorded here rather than
committed as a binary fixture:

```text
Kernelcon 2024 Forensics 100 VOIP Capture | SIP/SDP/RTP G.711 + telephone-event/FSK | https://github.com/natesubra/kernelcon_ctf_2024/tree/main/files | 2fb71a170e810fefc63f265e47a4d7b5a1b907e0c4652cd085818b32722e7ba1 | repository has no SPDX license declaration; local-only | %LOCALAPPDATA%\AutoShark\samples\public\kernelcon-ctf-2024\cyberdyne_voip.pcap | analyze/index-summary/voip-extract/report verified; 3 WAV artifacts, one complete and two sequence-gap partials
BSides San Francisco CTF 2017 dnscap | DNS hex labels + retransmission-aware framing + PNG recovery | https://github.com/ctf-wiki/ctf-challenges/tree/master/misc/cap/BSides-San-Francisco-CTF-2017-dnscap | 2913744793e3b95676d0713aef7c7df42ddb2f8ffece2b022c7ee727b833f59 | mirror has no SPDX license declaration; local-only | %LOCALAPPDATA%\AutoShark\samples\public\bsidessf-2017-dnscap\dnscap.pcap | dns-triage verified: one score-100 group, inferred 9-byte header, one CRC-valid 11,497-byte PNG
2016 CFF 简单网管协议 | SNMPv1 public community + MIB OctetString sensitive value | https://github.com/ctf-wiki/ctf-challenges/tree/master/misc/cap/2016CFF-%E7%AE%80%E5%8D%95%E7%BD%91%E7%AE%A1%E5%8D%8F%E8%AE%AE | 6c9791f0acf3af7edb36c99131c1307d74e06f7e32c4ef6b5ee6f11497d1db | mirror has no SPDX license declaration; local-only | user practice corpus\2016cff_simple_snmp.pcapng | solved independently at frame 3588; current queue emits `snmp-sensitive-values` priority 65
Hack Dat Kiwi CTF 2015 ssl-sniff-2 | legacy TLS RSA key exchange + HTTP recovery | https://github.com/ctf-wiki/ctf-challenges/tree/master/misc/cap/hack-dat-kiwi-ctf-2015-ssl-sniff-2 | 8f61a28709d86f99182a88febecc4c904086144fb8372a53d5b659615f27bf5e | mirror has no SPDX license declaration; local-only | user practice corpus\hackdatkiwi_2015_ssl_sniff2.pcap | solved with challenge RSA key and TShark 4.6 `uat:rsa_keys`; undecrypted baseline emits `tls-encrypted-traffic` priority 55
2016 CFF Struts2 漏洞 | URL-form field-name OGNL command execution + response correlation | https://github.com/ctf-wiki/ctf-challenges/tree/master/misc/cap/2016CFF-Structs2%E6%BC%8F%E6%B4%9E | c48b6be6407c40b214a3277b73d78f43862d88324c50e4c66d6f2066f9b62bd3 | mirror has no SPDX license declaration; local-only | user practice corpus\2016cff_struts2.pcapng | fresh project finds rank-99 `{FLAG:...}`, 3 command events, one critical endpoint finding, exact request/response evidence, no CSS `key{color:...}` candidate
2016 CFF 远程登录协议 | Telnet cleartext authentication + per-character input + terminal controls | https://github.com/ctf-wiki/ctf-challenges/tree/master/misc/cap/2016CFF-%E8%BF%9C%E7%A8%8B%E7%99%BB%E5%BD%95%E5%8D%8F%E8%AE%AE | d4266c1bf52913f0b89cd037ad5dc05927a3ba1446076ab4bea234a499eceb11 | mirror has no SPDX license declaration; local-only | user practice corpus\2016cff_remote_login_telnet.pcapng | 24,271-frame mixed capture; 1 complete stream, 636 metadata frames, prompt/login/password relations, four server flag candidates
CSAW CTF 2014 why not sftp | FTP cleartext login + PASV control/data correlation + ZIP transfer | https://github.com/ctfs/write-ups-2014/tree/master/csaw-ctf-2014/why-not-sftp | 77d2e59bf2f453d63782d636355052ff07f0ae387144f4bc272b02e131769596 | repository has no root SPDX license declaration; local-only | user practice corpus\csaw_2014_why_not_sftp_traffic5.pcap | 495-frame mixed capture; 63 FTP/FTP-DATA messages, two LIST transfers, one complete 12,092-byte ZIP RETR on stream 13; exposed multiline FEAT response parsing gap
Insomni'hack CTF 2015 Time to leak | ICMP Echo TTL ASCII + reply/no-reply boolean oracle | https://github.com/ctfs/write-ups-2015/tree/master/insomni-hack-ctf-2015/network/timetoleak | c9549814f2b9cef6c44e069678e3d3c6a08198973d315f05193480aef2f41f4c | repository has no root SPDX license declaration; local-only | user practice corpus\insomnihack_2015_time_to_leak.pcapng | 14 printable varying TTL guesses; explicit reply bitmap `00101010110111`; capture is a middle excerpt and cannot recover the historic full flag alone
PicoCTF 2021 Trivial Flag Transfer Protocol | TFTP WRQ/RRQ + negotiated UDP routes + 16-bit block wrap + BMP steganography | https://github.com/AshRahman/picoCTF | 2cf17f1a8837fb25613743df5c9b5d1a0748c783bfc02980689443adebd94156 | mirror has no SPDX license declaration; local-only | user practice corpus\picoctf_2021_tftp.pcapng | 152,413 frames; one complete WRQ, five complete RRQs, two server errors; all file hashes verified and picture2 block wrap reconstructed
```

The human workflow exposed by this sample is: inspect SIP/SDP, separate RTP
audio from telephone-event packets, reconstruct G.711 audio, then try a 300
baud FSK decoder when playback contains modem tones. A real Linux validation
used `minimodem 0.24` built in `/tmp` with `libsndfile-devel`, `fftw-devel`,
`alsa-lib-devel`, and `pulseaudio-libs-devel`; the decoder recovered the
capture's plaintext instructions and encrypted hex, but the final challenge
answer is intentionally not recorded here.

The DNS sample originally produced zero manual tasks because DNS was excluded
from the generic unsupported-protocol queue. The corpus-driven `dns-triage`
slice now groups queries by source, destination, base domain, and encoding;
scores encoded-label count, byte volume, route ratio, uniqueness, and length;
deduplicates blocks in first-seen order; and stores a bounded decoded preview.
Hex, Base32, and URL-safe Base64 labels are recognized. File promotion is more
conservative: only a uniquely reconstructed PNG with valid chunk CRCs becomes
an artifact. The verified PNG is 11,497 bytes with SHA-256
`d3ff9f96c3b0e1ed4f6f8dcc6dce07a33d5e223e8299340d35169980ca6809d7`.

Normal DNS, CDN, and tracking captures remain required negative controls. A
high score is a review signal, not proof of exfiltration. Capture-first-seen
ordering and an inferred fixed header are recorded in the locator; ambiguous
ordering, multiple recovered candidates, non-PNG bytes, or exhausted budgets
stay as preview evidence and must not be presented as a recovered file.

The ICMP oracle analyzer requires at least eight requests on one route, at
least 90 percent printable TTL values, four distinct TTL values, and both
answered and unanswered probes. It follows `icmp.resp_to` rather than timing
proximity. Ordinary fixed-TTL ping remains a required negative control, and a
partial oracle transcript must never be expanded with answer text from a
write-up.

The first five samples remain the deterministic release gate. Additional
public or user-owned captures should run through the same `analyze -> protocol
extractors -> scan -> triage -> detect -> index-summary -> report/export`
workflow and contribute
only bounded, explainable expectations.

## Linux enhancement policy

The CentOS node is an optional analyzer host, not a replacement for the
Windows controller. Probe absolute executable paths first. Prefer small
declared jobs (`file`, `strings`, `zsteg`, archive metadata) before a full
toolkit pass; every job has an output/timeout budget and its terminal output is
preserved as evidence. A missing tool is a reported capability gap, not a
reason to alter unrelated services or execute captured content.
