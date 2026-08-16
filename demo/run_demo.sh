#!/bin/bash
# GCP Post-Quantum Cryptography Migration Assessment Demo Run

echo "======================================================================"
# Corrected the branding to reflect honest positioning
echo "🛡️ GCP PQC Migration Assessment Tool Demonstration"
echo "======================================================================"
echo ""

# 1. Run the compliance scanning assessor in Demo Mode
echo "[Step 1] Inspecting GCP Project crypto assets (Simulated Demo Mode)..."
python scanners/gcp_pqc_inventory_scanner.py --demo

echo ""
# 2. Run Shor's algorithm gate depth estimation for RSA-2048 with 10y longevity
echo "[Step 2] Estimating quantum resources & HNDL priority via lit estimates..."
python simulation/cirq_quantum_estimator.py --bits 2048 --data-longevity 10

echo "======================================================================"
echo "✅ PQC Verification Demo Executed Successfully."
echo "======================================================================"
