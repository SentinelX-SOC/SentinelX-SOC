
# LANL Cyber 1: Safe Initial Exploration

## Files and schemas

LANL Cyber 1 contains de-identified Windows authentication events and known
red-team compromise events. The files are comma-delimited gzip archives and
are read directly without permanently uncompressing them.

### `auth.txt.gz`

Each row has nine fields:

| Field | Type | Meaning | Example |
| --- | --- | --- | --- |
| `timestamp` | integer | Relative time in seconds; LANL states the dataset uses epoch 1 and does not disclose calendar dates | `1` |
| `source_user` | string | User account initiating the authentication | `C101$@DOM1` |
| `destination_user` | string | User account receiving the authentication | `SYSTEM@C1020` |
| `source_computer` | string | Computer from which the authentication originated | `C1020` |
| `destination_computer` | string | Computer receiving the authentication | `C1020` |
| `authentication_type` | string | Authentication protocol or mechanism | `Kerberos` |
| `logon_type` | string | Windows logon category | `Network` |
| `authentication_orientation` | string | Whether the event is a logon or logoff | `LogOn` |
| `status` | string | Authentication result | `Success` |

LANL documents `?` as the value for a field without a valid value. The loader
preserves it rather than treating it as a guessed semantic category.

### `redteam.txt.gz`

Each row has four fields:

| Field | Type | Meaning | Example |
| --- | --- | --- | --- |
| `timestamp` | integer | Relative event time in seconds | `151648` |
| `user` | string | De-identified user account associated with the compromise event | `U748@DOM1` |
| `source_computer` | string | Source computer in the compromise event | `C17693` |
| `destination_computer` | string | Destination computer in the compromise event | `C728` |

LANL describes these records as specific events taken from the authentication
data and intended as known bad-behavior ground truth. They do not include an
authentication status or protocol field.

## Why start here?

Authentication events provide user-to-computer and computer-to-computer
relationships. The red-team events provide a small, documented reference set
for checking whether later threat-hunting logic finds known compromises. These
relationships are useful building blocks for an eventual enterprise graph.

The complete auth archive is intentionally not loaded by default: LANL reports
that the full dataset contains more than 1.6 billion events. Use
`max_rows` while exploring, or build a separate chunked aggregation workflow
when a full-data computation is necessary.

## Running the loader

From the project root:

```python
from src.data_loader import load_auth_events, load_redteam_events

auth_sample = load_auth_events("data/raw/auth.txt.gz", max_rows=1000)
redteam = load_redteam_events("data/raw/redteam.txt.gz")
```

Run `notebooks/01_lanl_exploration.ipynb` after placing both archives in
`data/raw/`. The current workspace inspection found `auth.txt.gz` one level
above the project, at `D:\\Hackathons\\SOC Analyst\\auth.txt.gz`; move or copy
it into the project data directory before running the notebook.
