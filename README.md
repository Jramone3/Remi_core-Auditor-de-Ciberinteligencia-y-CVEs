# 🛡️ REMI-Lite Audit Portable

**Plug & Play autonomous cyber intelligence and vulnerability assessment engine** optimized for legacy hardware, air-gapped environments, and low-resource systems.

## 🚀 Key Features
- **Zero-Dependency Execution:** Stand-alone compiled binary. No Python installation, virtual environments, or heavy runtimes required.
- **Dual-Pass Verification:** Built-in secondary heuristic filter to cross-reference local packages and eliminate historical false positives.
- **Instant Reporting:** Generates clean, standalone executive HTML reports with actionable mitigation strategies.

---

## 📦 Quick Start (Plug & Play)

### Linux (x86_64)
1. Download the executable `remi-audit-linux` and its cryptographic verification file `remi-audit-linux.sha256`.
2. Verify integrity:

   ```bash
   sha256sum -c remi-audit-linux.sha256
```

Grant execution permissions and run:

Bash

chmod +x remi-audit-linux
./remi-audit-linux

Open the generated Reporte_Auditoria_REMI_*.html in any web browser to view executive findings.

🔐 Cryptographic Integrity
Binary: remi-audit-linux

SHA-256 Hash: 5d69f1620626cd5b4ad06e80cc0228ba8a193554ff8d1eb76323c66cc20280a7

Developed by REMI_CORE Ecosystem.
