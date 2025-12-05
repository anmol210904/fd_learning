# vector_model.py
"""
A lightweight vector-only ML model for the demo/wrapper.
- No torch dependency.
- Exposes: get_flat_weights(), set_flat_weights(), run_epoch(), reinitialize().
"""

import random
import time
from typing import List
from config import VECTOR_SIZE, TRAIN_TIME_ESTIMATE

class VectorModel:
    def __init__(self, vector_size: int = None):
        self.vector_size = vector_size or VECTOR_SIZE
        # initialize with small random floats
        self.weights = [random.uniform(-0.1, 0.1) for _ in range(self.vector_size)]

    def get_flat_weights(self) -> List[float]:
        """Return current weights as list of floats."""
        return list(self.weights)

    def set_flat_weights(self, flat: List[float]):
        """Load a list of floats into model weights."""
        if len(flat) != self.vector_size:
            raise ValueError(f"Expected {self.vector_size} floats, got {len(flat)}")
        self.weights = [float(x) for x in flat]

    def reinitialize(self):
        """Randomize weights (for new round)."""
        self.weights = [random.uniform(-0.1, 0.1) for _ in range(self.vector_size)]

    def run_epoch(self, simulate: bool = True, noise_scale: float = 1e-3):
        """
        Simulate training by adding small noise to weights and waiting
        TRAIN_TIME_ESTIMATE seconds to mimic compute.
        If you later pass real training, replace this method.
        Returns elapsed time.
        """
        start = time.time()
        if simulate:
            # small perturbation to simulate parameter update
            for i in range(self.vector_size):
                self.weights[i] += random.gauss(0, noise_scale)
            time.sleep(TRAIN_TIME_ESTIMATE)
        elapsed = time.time() - start
        return elapsed
