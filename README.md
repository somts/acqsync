# Introduction
**acqsync** is a Python3-based utility that is designed to copy data
from multiple sources and place copies in a central and organized
location, such as a NAS. It is designed to run best on a NAS.

If your NAS cannot manage Python 3 installations, running a dedicated
Linux system with autofs configured such that paths to your NAS appear
to be a local system path is the suggested workaround.

## Design principles

1. Uses YAML for configuration in order to provide structured data to the tool
2. Allows for Jinja2-style variable expansion in some configuration sections EG `dst: /share/cruise/{{ cruise.id }}/data`
3. Can be configured modularly on a cruise-by-cruise basis with minimal edits
4. Sanity checks configuration for proper rsync syntax
5. Allows for globbing of files EG `*.pdf`
6. Allows for gathering of files based on a date-range EG `filename_%Y-%m%d`
7. Builds and executes multiple rsync jobs in parallel, using multithreading

# Installation Notes

Operationally, this repo is generally best installed **as a git repo**
in a consistent location (EG `/opt/acqsync`) by an automated configuration
management tool (EG Puppet), which is also likely to manage things like
*autofs*, *crontab*, and the role account that should run this tool. A
setup like this provides consistent setup aboard multiple ships.

However, this also means that changes made on the local OS to files
**not** listed in <.gitignore> will be undone and reverted back to
whatever the supported git commit is. So, local changes, other than
to `etc/acqsynq.yaml`, are generally not supported and a contribution
will be needed to affect code changes.

# Contributing

If you notice a bug or want a feature added, please visit
<https://github.com/somts/acqsync> and raise a PR or Issue.

# Usage

If installed in `/opt/acqsync`, run `/opt/acqsync/bin/acqsync -h` for
CLI options useful for debugging.

# Configuration

If installed in `/opt/acqsync`, the default configuration file will be
`/opt/acqsync/etc/acqsync.yaml`.  Please see example configurations at
`/opt/acqsync/etc/acqsync.example*.yaml`
