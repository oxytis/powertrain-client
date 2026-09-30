# powertrain-client

CLI and Python client for the [Oxytis](https://oxytis.com) Powertrain finding and CVE analysis API. It applies the same client-side redaction as the Powertrain Burp extension, but runs without Burp.

No dependencies beyond the Python 3 standard library.

## Setup

Get an API token from Oxytis and set it as an environment variable. This keeps it out of your shell history, which `--token` does not.

```bash
export POWERTRAIN_TOKEN=your-token
```

## CLI usage

Assess a finding. The first line of the text is used as the finding name.

```bash
echo "Reflected XSS in /search q param
The q parameter is reflected unencoded in the results page." | python3 powertrain.py
```

Analyze a CVE:

```bash
python3 powertrain.py --cve CVE-2024-3094
```

Options:

| Flag | Values | Default |
|------|--------|---------|
| `--exposure` | `external`, `internal`, `unknown` | `external` |
| `--controls` | `partial`, `ineffective`, `effective` | `partial` |
| `--mode` | `redacted`, `metadata-only`, `raw` | `redacted` |
| `--evidence` | path to a file with request/response evidence | none |
| `--name`, `--cwe` | override the name, or set a CWE instead of letting the model infer one | none |

## Python usage

```python
from powertrain import assess_finding, analyze_cve

result = assess_finding("Reflected XSS in /search q param\n...", host="target.example.com")
cve = analyze_cve("CVE-2024-3094")
```

## Redaction

In `redacted` mode, the client strips the following before anything is sent: JWTs, email addresses, IPv4 addresses, MAC addresses, serial numbers, UUIDs, long hex strings, base64 blobs, and values of sensitive-looking keys such as `password=` and `token:`. Pass `host=` to redact the target hostname as well.

Redaction is best-effort and regex-based. It won't catch everything; for example, it misses hostnames when `host` isn't passed, IPv6 addresses, and some key formats. Review sensitive findings before sending them.

- `metadata-only` sends the redacted finding text but no evidence.
- `raw` sends everything **unredacted**.

## License

MIT
