# SecureFL: A Post-Quantum Verifiable Federated Learning Platform

A secure, verifiable, and privacy-preserving Federated Learning as a Service (FLaaS) platform, architected to be resilient against future quantum computing threats. This project implements the core principles of the **Group Verifiable Secure Aggregation (GVSA)** protocol to enable collaborative machine learning without compromising raw data.

---

## 📖 Table of Contents
- [Introduction](#introduction)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [How It Works: The Secure Aggregation Protocol](#how-it-works-the-secure-aggregation-protocol)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the Simulation](#running-the-simulation)
  - [Mounting Your Own Model](#mounting-your-own-model)
- [Demonstration Use Case](#demonstration-use-case)
- [Future Work](#future-work)

---

## 💡 Introduction
This platform addresses the critical challenge of training powerful AI models on sensitive, siloed data. In fields like healthcare and finance, data privacy regulations and ethical concerns prevent the centralization of data. **Federated Learning (FL)** solves this by sending the model to the data, allowing for collaborative training without sharing private information.

This project implements a complete FL system with a strong focus on security, ensuring that the process is **private, verifiable, and robust** against malicious actors and future threats.

---

## ✨ Key Features
- **Privacy-Preserving Aggregation:** Utilizes Shamir's Secret Sharing to mask user model weights, ensuring the server can aggregate results without seeing individual contributions.
- **Verifiable Computation:** Implements lightweight verification tags, allowing clients to cryptographically verify that the server has performed aggregation honestly.
- **Fault Tolerance:** Protocol is robust to user dropouts, a common issue in real-world distributed systems.
- **Post-Quantum Ready:** Designed with crypto-agility, enabling upgrade from classical algorithms (ECDSA/ECDH) to **NIST-selected PQC standards** like CRYSTALS-Dilithium/Kyber.
- **Containerized & Flexible:** Client module can run any user-defined **PyTorch** or **TensorFlow** model.
- **Autonomous Operation:** Server and clients operate as autonomous entities, synchronizing through a timed, state-based window system.

---

## 🏗️ System Architecture
The platform uses a **hierarchical client-server model** designed for scalability:

- **Aggregator Server:** Central server orchestrating the process. Manages an autonomous state machine, cycling through timed "windows" for each round phase. Never sees unencrypted private data.
- **User Client:** Autonomous client module (containerized) that holds user's private data and ML model. Synchronizes with server's windows using a "hit-and-retry" mechanism.

---

## 🛡️ How It Works: The Secure Aggregation Protocol
A single federated learning round involves multiple stages:

1. **Registration & Authentication:** Clients join a round and authenticate with a digitally signed public key (ECDSA).
2. **Secure Key Exchange:** Server broadcasts public keys. Clients establish encrypted peer-to-peer channels using **ECDH**.
3. **Masking & Share Distribution:** Each client trains its local model, generates a random secret mask, splits it via **Shamir's Secret Sharing**, and sends encrypted shares to the server.
4. **Share Relaying:** Server forwards encrypted shares to intended recipients.
5. **Final Data Submission:** Clients decrypt received shares and submit masked model, verification tag, and sum of decrypted shares to server.
6. **Secure Aggregation:** Server reconstructs sum of all masks and subtracts from masked models to get aggregated result using secure modular arithmetic.
7. **Verification:** Server sends global model and aggregated tag back. Clients verify computation correctness before accepting the new model.

---

## 🛠️ Technology Stack

| Component        | Technology                                       |
|-----------------|-------------------------------------------------|
| Server           | Python, Flask                                   |
| Client           | Python (containerized)                          |
| ML Framework     | PyTorch (adaptable to TensorFlow)              |
| Cryptography     | `cryptography` library (ECDSA, ECDH, AES-GCM)  |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.9+
- `pip` for installing packages

### Installation
```bash
git clone https://github.com/anmol210904/fd_learning.git
cd fd_learning
pip install -r requirements.txt
