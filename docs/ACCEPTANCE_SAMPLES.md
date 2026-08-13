# Local Acceptance Captures

The captures are private local fixtures and are not committed. Expected answer
values are test oracles only; production analysis cannot read the answer file.

## Capture manifest

| Capture | Frames | Bytes | SHA-256 |
|---|---:|---:|---|
| `networking.pcap` | 59 | 4,570 | `7072E7E1A42EFE6B77BC0A428B5297440F123098143E830C1E9B7C7AE6886165` |
| `dianli_jbctf_MISC_T10075_20150707_wireshark.pcap` | 356 | 64,441 | `E95B0D7F7A138857644B26E2CEBBD56BCD18E4E29A860C076B349967F19B28EB` |
| `被偷走的文件.pcapng` | 301 | 34,560 | `0F2D01CBC13028DEAB3AF0E105BBA33F13FCBE3195E726DCEAF0DCD7EA257C98` |
| `被嗅探的流量.pcapng` | 335 | 211,264 | `AEC4FC3FA0C92108D57B2F48AE3DFFFB03458C7F5C2441C1BE220E83437ED20F` |
| `菜刀666.pcapng` | 2,139 | 2,364,868 | `02435B42FC99B5245367801BED58E853E4427052F3D6F58CEB10E26624405269` |

## Acceptance specifications

### Telnet

Reconstruct the directional dialogue in TCP stream 0. Preserve the login and
password prompts and rank the cleartext flag-like input in frame 41 first.

### HTTP form login

Pair request frame 20 with response frame 26. Decode the ordered form fields
`email`, `password`, and `captcha`; distinguish this credential event from
ordinary analytics/background requests and rank the password value first.

### FTP transfer

Correlate PASV response frame 44, `RETR flag.rar` frame 49, and FTP-DATA frame
55. Export exactly 164 bytes as RAR, preserve provenance, and verify SHA-256
`941702F949E60D081210D33A98552B32D3E5B36673BE2E6C0F439904F46B5597`.
Queue the archive for manual review without cracking or executing content.

### Multipart JPEG with trailing data

Preserve three `/upload.php` transactions: 36/38, 54/56, and 233/260. The
target request frame 233 contains a 164,161-byte multipart body with form field
`upfile`, filename `flag.jpg`, and declared type `image/jpeg`.

The part starts at body offset 138. Its valid JPEG ends at EOI offset 164,074;
the JPEG is 163,938 bytes with SHA-256
`D8E9BA607BDE8BCCB1BF812E7D0D354ABF41A57C0461E6B59C1FA9D5DCC58888`.
Search and preserve the bytes after EOI before dispatching the image adapter.
Rank the flag-like trailing text first. Response frame 260 is HTTP 500 but its
HTML says `upload success`; report the status/body contradiction rather than
silently classifying the upload as failed.

The JPEG hash was independently revalidated on 2026-08-13 by locating the
capture by its manifest SHA-256, exporting frame 233 `http.file_data` with
TShark 4.6.7, and hashing byte range `[138, 164076)`. The formerly recorded
`E5B8...4B98` value did not match the capture or common boundary variants.

### WebShell traffic

Find 19 `POST /upload/1.php` transactions across reused TCP connections. Decode
bounded URL/Base64 parameters, reconstruct a chronological deduplicated action
timeline, retain the large request, preserve ZIP and PHP response artifacts,
and either solve fully or produce a complete ordered nonduplicated next-action
path. Each action must link to request/response frames and original bytes.
