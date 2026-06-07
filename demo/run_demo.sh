#!/bin/bash
# GCP Post-Quantum Cryptography Migration Assessment Demo Run

echo "======================================================================"
echo "🛡️ GCP PQC Migration Assessment Tool Demonstration"
echo "======================================================================"
echo ""

# 1. Run the compliance scanning assessor
echo "[Step 1] Inspecting GCP Asset Inventory for classical algorithms..."
python scanners/gcp_pqc_inventory_scanner.py --max-log-lines 200

echo ""
# 2. Run Shor's algorithm gate depth estimation for RSA-2048
echo "[Step 2] Estimating quantum breach timeline via Shor simulation..."
python simulation/cirq_quantum_estimator.py --bits 2048

echo "======================================================================"
echo "✅ PQC Verification Demo Executed Successfully."
echo "======================================================================"
