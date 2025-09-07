SecureFL: A Post-Quantum Verifiable Federated Learning Platform
A secure, verifiable, and privacy-preserving Federated Learning as a Service (FLaaS) platform, architected to be resilient against future quantum computing threats. This project implements the core principles of the Group Verifiable Secure Aggregation (GVSA) protocol to enable collaborative machine learning without compromising raw data.

📖 Table of Contents
Introduction

Key Features

System Architecture

How It Works: The Secure Aggregation Protocol

Technology Stack

Getting Started

Prerequisites

Installation

Running the Simulation

Mounting Your Own Model

Demonstration Use Case

Future Work

💡 Introduction
This platform addresses the critical challenge of training powerful AI models on sensitive, siloed data. In fields like healthcare and finance, data privacy regulations and ethical concerns prevent the centralization of data. Federated Learning (FL) solves this by sending the model to the data, allowing for collaborative training without sharing private information.

This project implements a complete FL system with a strong focus on security, ensuring that the process is not only private but also verifiable and robust against malicious actors and future threats.

✨ Key Features
Privacy-Preserving Aggregation: Utilizes Shamir's Secret Sharing to mask user model weights, ensuring the server can aggregate results without ever seeing individual contributions.

Verifiable Computation: Implements lightweight verification tags, allowing clients to cryptographically verify that the server has performed the aggregation honestly.

Fault Tolerance: The protocol is inherently robust to user dropouts, a common issue in real-world distributed systems.

Post-Quantum Ready: Designed with crypto-agility, with a clear roadmap to upgrade classical algorithms (ECDSA/ECDH) to NIST-selected PQC standards like CRYSTALS-Dilithium/Kyber.

Containerized & Flexible: The client is designed to be a containerized module that can run any user-defined PyTorch or TensorFlow model.

Autonomous Operation: The server and clients operate as autonomous entities, synchronizing through a timed, state-based window system.

🏗️ System Architecture
The platform uses a hierarchical, client-server model designed for scalability.

Aggregator Server: A central server that orchestrates the entire process. It manages an autonomous state machine, cycling through timed "windows" for each phase of a round. It facilitates communication but never sees unencrypted private data.

User Client: An autonomous client module (designed to be containerized) that holds the user's private data and ML model. It synchronizes with the server's windows using a "hit-and-retry" mechanism.

🛡️ How It Works: The Secure Aggregation Protocol
A single federated learning round is a multi-stage process orchestrated by the server:

Registration & Authentication: Clients join a round and authenticate themselves by providing a digitally signed public key (using ECDSA).

Secure Key Exchange: The server broadcasts the authenticated public keys of all participants. Each client then establishes a unique, encrypted peer-to-peer channel with every other participant using an ECDH key exchange.

Masking & Share Distribution: Each client trains its local model, generates a random secret mask, and splits it into shares using Shamir's Secret Sharing. It then sends each encrypted share to the server.

Share Relaying: The server acts as a "post office," forwarding the encrypted shares to their intended recipients.

Final Data Submission: After decrypting the shares they've received, each client submits its masked model, a verification tag, and the sum of its decrypted shares to the server.

Secure Aggregation: The server uses the summed shares to reconstruct the sum of all masks (due to the homomorphic property of SSS). It subtracts this from the sum of masked models to get the true aggregated result, all performed with secure modular arithmetic.

Verification: The server sends the final global model and an aggregated tag back to the clients. Each client performs a local check to verify the server's computation was correct before accepting the new model.

🛠️ Technology Stack
Component

Technology

Server

Python, Flask

Client

Python (designed for containerization)

ML Framework

PyTorch (easily adaptable to TensorFlow)

Cryptography

cryptography library (for ECDSA, ECDH, AES-GCM)

🚀 Getting Started
Prerequisites
Python 3.9+

pip for installing packages

Installation
Clone the repository:

git clone [https://github.com/anmol210904/fd_learning.git](https://github.com/anmol210904/fd_learning.git)
cd fd_learning

Install the required libraries:

pip install -r requirements.txt

(Note: You will need to create a requirements.txt file containing Flask, requests, cryptography, torch, pandas, scikit-learn, joblib, etc.)

Running the Simulation
Start the Server: Open a terminal and run the aggregator server.

python api_server.py

The server will start its autonomous loop, opening and closing windows.

Run the Clients: Open one or more separate terminals to simulate multiple users. In each terminal, run the autonomous client script.

# In Terminal 2
python UserLogic.py

# In Terminal 3 (optional, for another user)
python UserLogic.py
