import torch
import torch.nn as nn
import os

# --- THE ML MODEL CLASS ---

class MLModel:
    """
    A class that encapsulates a PyTorch model for loading and prediction.
    """
    def __init__(self, model_architecture):
        """
        Initializes the model.
        
        Args:
            model_architecture: A PyTorch nn.Module object defining the model.
        """
        self.model = model_architecture
        
    def load_from_disk(self, file_path):
        """
        Loads saved weights from a file into the model in RAM.
        """
        if os.path.exists(file_path):
            # Loads the state_dict (dictionary of weights) from the .pth file
            # and applies it to the model instance.
            self.model.load_state_dict(torch.load(file_path))
            print(f"--- MLModel: Successfully loaded weights from '{file_path}'. ---")
        else:
            print(f"--- MLModel ERROR: Backup file not found at '{file_path}'. Using initial random weights. ---")
            
    @classmethod
    def predict_from_file(cls, model_architecture, file_path, input_data):
        """
        A utility method to create a model, load its saved weights, and make a prediction.
        
        Args:
            model_architecture: The nn.Module class for the model.
            file_path (str): The path to the saved .pth model file.
            input_data (torch.Tensor): The input data for the model.

        Returns:
            torch.Tensor: The output (prediction) from the model.
        """
        print("\n--- Performing standalone prediction from file... ---")
        
        # 1. Create a new instance of the model handler
        model_handler = cls(model_architecture)
        
        # 2. Load the saved weights from the specified file
        model_handler.load_from_disk(file_path)
        
        # 3. Make the prediction
        with torch.no_grad():
            model_handler.model.eval() # Set the model to evaluation (inference) mode
            output = model_handler.model(input_data)
        
        print("--- Prediction complete. ---")
        return output

# --- DEMONSTRATION OF HOW TO USE THE SCRIPT ---
if __name__ == "__main__":
    
    # 1. DEFINE THE PATH TO YOUR SAVED MODEL
    # This file should have been created by your training script.
    saved_model_path = "model_backup.pth"

    # 2. DEFINE THE MODEL ARCHITECTURE
    # This MUST be the exact same architecture as the model that was saved.
    user_architecture = nn.Sequential(nn.Linear(10, 5), nn.ReLU(), nn.Linear(5, 1))
    
    # 3. CREATE A NEW, SINGLE INPUT FOR PREDICTION
    # It must have the correct shape (in this case, 1 sample with 10 features).
    new_input_data = torch.randn(1, 10) 
    print(f"--- Input data for prediction: {new_input_data} ---")

    # 4. CALL THE PREDICT FUNCTION
    # This single function handles creating the model, loading the file, and predicting.
    prediction = MLModel.predict_from_file(
        model_architecture=user_architecture,
        file_path=saved_model_path,
        input_data=new_input_data
    )

    print(f"\n>>> Final prediction output: {prediction.item()}")
