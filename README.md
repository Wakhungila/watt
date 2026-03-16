WATT - Web Attack & Threat Telescope
====================================

```
██     ██ ▄████▄ ██████ ██████ 
██ ▄█▄ ██ ██▄▄██   ██     ██   
 ▀██▀██▀  ██  ██   ██     ██

Web Attack & Threat Telescope
Intelligence density over scanning volume.
```

WATT is an attack-surface intelligence platform for elite bug bounty hunters, red team operators, and advanced web application security researchers.

Unlike traditional recon tools that produce flat lists, WATT builds **relationships** between assets to reveal the hidden architecture of complex systems.

This repository is under active development. Phase 1 focuses on:

- Core configuration and workspace management
- Structured logging
- Core controller and module registry
- CLI skeleton and target ingestion

See `docs/` for architecture notes as the project evolves.

## Installation

WATT requires Python 3.9+ and Poetry for dependency management.

```bash
# Clone the repository
git clone https://github.com/Wakhungila/watt.git
cd watt

# Install dependencies
poetry install

# Activate the virtual environment
source $(poetry env info --path)/bin/activate

# Note: The command above activates the environment for your current shell session.
# You will need to run it again if you open a new terminal.
# Alternatively, you can run commands directly within the environment using `poetry run`.
# For example: `poetry run watt targets example.com`
```

## Usage

WATT uses a modular CLI interface.

### Ingest Targets

First, ingest your targets to normalize them and prepare the workspace.

```bash
watt targets example.com api.example.com
```

### Run a Scan

Run all registered modules against the targets.

```bash
watt run example.com
```

You can also specify specific phases or resume previous scans.

```bash
watt run example.com --phase recon
watt resume --workspace ./watt-workspace
```
