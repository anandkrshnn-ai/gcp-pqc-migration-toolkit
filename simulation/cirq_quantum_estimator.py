import argparse
import sys
import math

def estimate_shors_requirements(bit_length, is_ecc=False):
    """
    Estimates the gate-depth and logical/physical qubits required to factor or solve discrete logs.
    
    Citations & Assumptions:
    - Gidney & Ekerå (2021), 'How to factor 2048-bit RSA integers in 8 hours using 20 million noisy qubits'.
    - Roetteler et al. (2017) for ECC scaling benchmarks.
    - Under surface-code error models (physical error rate of 1e-3, code distance d=27, and magic state factory overheads).
    """
    if is_ecc:
        # ECC-256 or similar curves
        logical_qubits = int(6 * bit_length)
        # Gate complexity is O(n^3) but has different constant factors
        gate_depth = int(0.5 * (bit_length ** 3))
        # Surface code scaling factor ~3000 to 4000 physical qubits per logical qubit
        physical_qubits = logical_qubits * 4000
    else:
        # RSA-n
        # Logical qubits needed: 2n + 2
        logical_qubits = 2 * bit_length + 2
        # Gate complexity: ~O(n^3)
        gate_depth = int(bit_length ** 3)
        # Gidney & Ekerå 2021: RSA-2048 requires ~20M physical qubits (approx 4900 physical qubits per logical qubit)
        physical_qubits = logical_qubits * 4900

    return logical_qubits, physical_qubits, gate_depth

def simulate_toy_quantum_step():
    """
    Simulates a small toy 3-qubit quantum circuit to demonstrate gate operations.
    """
    try:
        import cirq
        qubits = [cirq.GridQubit(0, i) for i in range(3)]
        circuit = cirq.Circuit()
        circuit.append(cirq.H(qubits[0]))
        circuit.append(cirq.H(qubits[1]))
        circuit.append(cirq.CNOT(qubits[0], qubits[2]))
        circuit.append(cirq.CNOT(qubits[1], qubits[2]))
        circuit.append(cirq.measure(qubits[0], qubits[1], qubits[2], key='result'))
        
        simulator = cirq.Simulator()
        result = simulator.run(circuit, repetitions=10)
        return str(result)
    except ImportError:
        return "Cirq is not installed. Skipping toy simulation."

def get_hndl_priority(data_longevity):
    if data_longevity >= 10:
        return "IMMEDIATE (Data sensitivity lifetime exceeds predicted cryptanalytically useful quantum computer arrival)", "CRITICAL"
    elif data_longevity >= 5:
        return "HIGH (Data remains sensitive for 5-10 years; strong HNDL intercept target)", "HIGH"
    elif data_longevity >= 2:
        return "MEDIUM (Data longevity 2-5 years; transition timeline standard)", "MEDIUM"
    else:
        return "LOW (Short-lived data; minimal HNDL threat)", "LOW"

def main():
    parser = argparse.ArgumentParser(description="Post-Quantum Resource Estimator & HNDL Risk Prioritization")
    parser.add_argument("--bits", type=int, default=2048, help="Key size bit depth (e.g. 1024, 2048, 4096 for RSA; 256, 384 for ECC)")
    parser.add_argument("--ecc", action="store_true", help="Estimate for Elliptic Curve Cryptography (ECC) key rather than RSA.")
    parser.add_argument("--data-longevity", type=int, default=10, help="Number of years the data encrypted by this key must remain secure.")
    parser.add_argument("--run-toy", action="store_true", help="Optionally run the toy 3-qubit Cirq simulation.")
    args = parser.parse_args()

    if args.bits <= 0:
        print("[Error] Key bit length must be positive.", file=sys.stderr)
        sys.exit(1)

    print("\n========================================================")
    print("Shor's Algorithm Resource Estimation & HNDL Risk Analyzer")
    print("========================================================")
    print(f"Algorithm Profile: {'ECC' if args.ecc else 'RSA'}")
    print(f"Key Bit Depth: {args.bits}")
    print(f"Required Data Longevity: {args.data_longevity} years")
    
    logical, physical, depth = estimate_shors_requirements(args.bits, args.ecc)
    
    print("\n--- Estimated Quantum Resources ---")
    print(f"Logical Qubits Required: {logical:,}")
    print(f"Physical Qubits Required (under surface-code, 1e-3 error rate): {physical:,}")
    print(f"Toffoli/T-Gate Execution Depth: ~{depth:,}")
    
    print("\n--- Lit References & Assumptions ---")
    print("- Qubit overhead maps to Gidney & Ekerå (2021) resource estimations for RSA-2048.")
    print("- Assumes a superconducting architecture, physical gate error rate of 10^-3, and code distance d=27.")
    
    priority_msg, threat_level = get_hndl_priority(args.data_longevity)
    print(f"\n--- HNDL Risk Assessment ---")
    print(f"Threat Level: {threat_level}")
    print(f"Mitigation Priority: {priority_msg}")

    if args.run_toy:
        print("\n[*] Executing optional toy 3-qubit quantum simulation step...")
        sim_result = simulate_toy_quantum_step()
        print(f"Simulation Measurement Output:\n{sim_result}\n")

if __name__ == "__main__":
    main()
