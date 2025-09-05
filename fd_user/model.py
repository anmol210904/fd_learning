import torch
import torch.nn as nn
import torch.optim as optim
import threading
import os


class MLModel:
    """
    A class that encapsulates the user's ML model and training logic.
    It follows the standard interface required by the federated learning service.
    """
    def __init__(self, model_architecture):
        """
        Initializes the model, optimizer, and the lock for thread-safe operations.
        
        Args:
            model_architecture: A PyTorch nn.Module object defining the model.
        """
        self.model = model_architecture
        self.optimizer = optim.SGD(self.model.parameters(), lr=0.01)
        self.criterion = nn.CrossEntropyLoss()
        self.lock = threading.Lock() # For thread-safe weight modifications
        
    def save_weights_to_disk(self, file_path):
        """
        Saves the model's current state to a specified file for fault tolerance.
        This is a blocking operation.
        """
            # print("  (Saving weights to disk...)")
        torch.save(self.model.state_dict(), file_path)
            # print("  (Save complete.)")

    def put_weights(self, structured_weights):
        """
        Loads a structured list of weights into the model's parameters.
        This single function works for both initial and updated weights.
        """
        with self.lock, torch.no_grad():
            # print("\n--- MLModel: Loading new weights into model... ---")
            for i, param in enumerate(self.model.parameters()):
                param.data.copy_(structured_weights[i])
            # print("--- MLModel: New weights loaded into RAM successfully. ---")
       


    def get_model_object(self):
        """
        Returns the raw model object. The orchestrator will use this
        with the WeightHandler to flatten the weights.
        """
        with self.lock:
            return self.model

    def run_epoch(self, data_loader):
        """
        Runs one full training epoch on the provided data loader.
        This modifies the model's weights in memory.
        """
        # print("\n--- MLModel: Starting one training epoch... ---")
        self.model.train()
        with self.lock:
            for data, target in data_loader:
                self.optimizer.zero_grad()
                output = self.model(data)
                loss = self.criterion(output, target)
                loss.backward()
                self.optimizer.step()
        # print("--- MLModel: Training epoch complete. ---")

    def load_from_disk(self, file_path):
        """
        Loads the last saved weights from the specified backup file.
        Useful for recovering from a crash.
        """
        if os.path.exists(file_path):
            # print(f"\n--- MLModel: Recovering model from backup file '{file_path}'... ---")
            with self.lock:
                self.model.load_state_dict(torch.load(file_path))
            # print("--- MLModel: Recovery successful. ---")
        else:
            # print("\n--- MLModel: No backup file found. Using initial random weights. ---")
            pass