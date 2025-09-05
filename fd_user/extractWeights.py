import torch
import torch.nn as nn
import tensorflow as tf
from tensorflow import keras

class WeightHandler:
    """
    A utility class to handle the flattening and de-flattening of model weights.
    It learns the model's architecture upon initialization to correctly
    reconstruct the weights later.
    """
    def __init__(self, model):
        """
        Initializes the handler with a model object.

        Args:
            model: A PyTorch or TensorFlow/Keras model object.
        """
        if not (isinstance(model, nn.Module) or isinstance(model, tf.keras.Model)):
            raise TypeError("Model must be a PyTorch or TensorFlow/Keras model.")
            
        self.model = model
        self.framework = 'pytorch' if isinstance(model, nn.Module) else 'tensorflow'
        
        # --- This is the key step ---
        # We store the shape and size of each weight layer.
        # This metadata is essential for de-flattening.
        self.layer_info = []
        if self.framework == 'pytorch':
            for param in self.model.parameters():
                self.layer_info.append({
                    'shape': param.shape,
                    'num_elements': param.numel()
                })
        else: # tensorflow
            for layer_weights in self.model.get_weights():
                self.layer_info.append({
                    'shape': layer_weights.shape,
                    'num_elements': layer_weights.size
                })

    def flatten_weights(self):
        """
        Extracts and flattens all weights from the model into a single list.
        """
        flat_weights = []
        if self.framework == 'pytorch':
            for param in self.model.parameters():
                flat_weights.extend(param.data.flatten().tolist())
        else: # tensorflow
            for layer_weights in self.model.get_weights():
                flat_weights.extend(layer_weights.flatten().tolist())
        return flat_weights

    def deflatten_weights(self, flat_weights_array):
        """
        De-flattens a list of weights back into the original model's structure.

        Args:
            flat_weights_array (list): A flat list of weights.

        Returns:
            list: A list of weight tensors/arrays, reshaped to match the model's architecture.
        """
        if not isinstance(flat_weights_array, list):
            raise TypeError("Input must be a flat list of weights.")

        structured_weights = []
        start_index = 0
        for info in self.layer_info:
            num_elements = info['num_elements']
            shape = info['shape']
            
            # Get the slice for the current layer
            param_slice = flat_weights_array[start_index : start_index + num_elements]
            
            # Reshape the slice and add it to our list
            if self.framework == 'pytorch':
                structured_weights.append(torch.tensor(param_slice).view(shape))
            else: # tensorflow
                import numpy as np
                structured_weights.append(np.array(param_slice).reshape(shape))
            
            start_index += num_elements
            
        return structured_weights

# --- DEMONSTRATION OF HOW A USER WOULD USE THIS ---
if __name__ == "__main__":
    
    # 1. USER CREATES THEIR MODEL
    # In this case, a simple PyTorch model.
    user_pytorch_model = nn.Sequential(nn.Linear(10, 5), nn.Linear(5, 1))
    
    # 2. YOUR SERVICE CREATES THE HANDLER
    # Your container would initialize the handler with the user's model.
    weight_handler = WeightHandler(user_pytorch_model)
    
    # 3. AFTER LOCAL TRAINING, YOUR SERVICE FLATTENS THE WEIGHTS
    # These are the weights that would be sent for aggregation.
    local_weights_flat = weight_handler.flatten_weights()
    print(f"Successfully flattened the model into an array of {len(local_weights_flat)} weights.")
    
    # 4. SIMULATE RECEIVING A GLOBAL MODEL FROM THE SERVER
    # This would be a flat array of the same size.
    global_model_flat = [1.0] * len(local_weights_flat)
    
    # 5. YOUR SERVICE DE-FLATTENS THE GLOBAL WEIGHTS
    # This prepares the weights in the correct structure for the user's model.
    global_model_structured = weight_handler.deflatten_weights(global_model_flat)
    print("\nSuccessfully de-flattened the global weights back to the model's original structure.")
    
    # 6. YOUR SERVICE PASSES THE STRUCTURED WEIGHTS TO THE USER'S MODEL
    # The user's `load_weights` function would then take this structured data.
    # For this demo, we'll load them directly to verify.
    with torch.no_grad():
        for i, param in enumerate(user_pytorch_model.parameters()):
            param.data.copy_(global_model_structured[i])
            
    # Verification
    final_weights = weight_handler.flatten_weights()
    assert all(w == 1.0 for w in final_weights), "Error: Weights did not update correctly!"
    print("\n✅ Verification successful: The new weights were correctly loaded into the model.")
