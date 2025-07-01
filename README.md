# SV2 Template Viewer

A Stratum V2 client that connects to bitcoin-mine and displays live Bitcoin block templates in real-time.

## Overview

This project demonstrates a working Stratum V2 implementation built from core SV2 crates, connecting directly to Sjors' Bitcoin Core SV2 integration to receive and parse actual Bitcoin block templates as they're generated.

## Features

- ✅ **Noise Protocol Encryption** - Complete NX handshake implementation
- ✅ **SV2 Message Framing** - Proper encrypted header/payload handling
- ✅ **Real-time Template Streaming** - Live Bitcoin block templates
- ✅ **Template Parsing** - Extract template ID, coinbase value, difficulty
- ✅ **Tip Change Detection** - Monitor Bitcoin network tip changes
- ✅ **Multi-message Processing** - Handle batched SV2 messages correctly

## Demo

![Template Viewer Output](docs/screenshots/template-viewer-output.png)
*Real-time template reception showing Template IDs, coinbase values (~50 BTC), and tip changes*

![Bitcoin Mine Logs](docs/screenshots/bitcoin-mine-logs.png)  
*Template provider logs showing NewTemplate and SetNewPrevHash message flow*

![Bitcoin Node Blocks](docs/screenshots/bitcoin-node-blocks.png)
*Bitcoin Core generating actual block templates with real transaction data*

## Architecture

This implementation connects three components:

1. **Bitcoin Core** (`bitcoin-node`) - Generates block templates
2. **Template Provider** (`bitcoin-mine`) - Serves templates via SV2 protocol  
3. **Template Viewer** (this project) - SV2 client displaying live data

```
Bitcoin Core → bitcoin-mine → SV2 Template Viewer
    (blocks)     (SV2 protocol)     (display)
```

## Technical Implementation

### Protocol Stack
- **Transport**: TCP with Noise Protocol encryption
- **Framing**: SV2 encrypted message framing (separate header/payload encryption)
- **Messages**: SetupConnection, NewTemplate, SetNewPrevHash, CoinbaseOutputConstraints

### Key Features
- Built from **core SV2 crates** (not full stratum framework)
- **Multi-message buffer processing** - handles batched SV2 messages  
- **Real Bitcoin integration** - connects to actual Bitcoin Core (not mock data)
- **Template parsing** - extracts meaningful data from binary SV2 messages

## Quick Start

### Prerequisites
- Rust (latest stable)
- Bitcoin SV2 binaries from [Sjors' releases](https://github.com/Sjors/bitcoin/releases)

### Run
```bash
# Start Bitcoin node (in separate terminal)
./bitcoin-node -testnet4 -ipcbind=unix

# Start template provider (in separate terminal)  
./bitcoin-mine -testnet4 -sv2port=8442 -sv2interval=20

# Run template viewer
git clone https://github.com/[username]/sv2-template-viewer
cd sv2-template-viewer
cargo run
```

## What You'll See

The template viewer displays live Bitcoin data:

- **Template IDs**: Sequential identifiers (1, 2, 3...)
- **Future vs Active**: Template state for mining readiness
- **Coinbase Values**: Block reward + fees (~50+ BTC on testnet4)
- **Tip Changes**: Real-time Bitcoin network progression
- **Block Data**: Versions, timestamps, difficulty

Example output:
```
🎯 NewTemplate message received!
📋 Template ID: 23
📋 Future template: false
📋 Block version: 0x20000000  
📋 Coinbase TX version: 2
📋 Potential coinbase value: 5007224698 satoshis (50.07224698 BTC)

🎯 SetNewPrevHash message received!
📋 Template ID: 23
📋 Previous hash: 000000000001fd7ac7ecc5817ff43bea0d152913edc9906d146966e1f3cf1735a
📋 Header timestamp: 1735689847
```

## Dependencies

```toml
[dependencies]
tokio = { version = "1.0", features = ["full"] }
tracing = "0.1"
tracing-subscriber = "0.3"  
anyhow = "1.0"
hex = "0.4"

# Core SV2 crates
roles_logic_sv2 = { git = "https://github.com/stratum-mining/stratum.git" }
binary_sv2 = { git = "https://github.com/stratum-mining/stratum.git" }
noise_sv2 = { git = "https://github.com/stratum-mining/stratum.git" }
key_utils = { git = "https://github.com/stratum-mining/stratum.git" }
```

## Why This Approach?

Instead of using the full stratum framework, this implementation:

- **Learns SV2 from first principles** - understand every protocol detail
- **Minimal dependencies** - only core crates, no framework bloat
- **Real Bitcoin integration** - actual block templates, not test data
- **Production foundation** - could scale to real mining infrastructure

Perfect for understanding how Stratum V2 actually works under the hood!

## Contributing

Issues and PRs welcome! This is an educational project showcasing SV2 protocol implementation.

## License

MIT