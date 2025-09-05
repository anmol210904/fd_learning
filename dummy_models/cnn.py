import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np

# --- 1. Define the Model Architecture ---
# This class defines the structure of our simple CNN.
# The weights (parameters) are automatically created and stored inside this object.
class SimpleCNN(nn.Module):
    def __init__(self):
        super(SimpleCNN, self).__init__()
        # Layer 1: A convolutional layer
        self.conv1 = nn.Conv2d(in_channels=1, out_channels=4, kernel_size=3, padding=1)
        # Layer 2: A fully connected (linear) layer
        self.fc1 = nn.Linear(in_features=4 * 14 * 14, out_features=10)

    def forward(self, x):
        # Defines the forward pass (how data flows through the model)
        x = torch.relu(self.conv1(x))
        x = torch.max_pool2d(x, kernel_size=2, stride=2)
        x = x.view(-1, 4 * 14 * 14) # Flatten the output for the linear layer
        x = self.fc1(x)
        return x

# --- 2. Helper Function to Extract Weights ---
def extract_weights_to_array(model):
    """
    This is the function your user module would call.
    It takes a model object and extracts all its weights into a single, flat list.
    """
    weights_list = []
    # model.parameters() gives you access to all the weight tensors in memory.
    for param in model.parameters():
        # .data gets the tensor, .flatten() makes it 1D, .tolist() converts to a Python list
        weights_list.extend(param.data.flatten().tolist())
    return weights_list

# --- 3. Main Training Script ---
if __name__ == "__main__":
    # --- INITIALIZATION ---
    # Create an instance of our CNN.
    # At this point, the model is in RAM with randomly initialized weights.
    model = SimpleCNN()

    print("--- MODEL CREATED ---")
    print("The model's weights are now initialized in RAM.")
    initial_weights = extract_weights_to_array(model)
    print(f"Total number of weights in the model: {len(initial_weights)}")
    print(f"First 5 initial weights: {[round(w, 4) for w in initial_weights[:5]]}\n")

    # Define a loss function and an optimizer.
    # The optimizer is the component that will update the weights.
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.SGD(model.parameters(), lr=0.01)

    # --- DATA PREPARATION (Dummy Data) ---
    # In a real scenario, this would be your user's private dataset.
    # We'll create 64 random 28x28 grayscale images and labels.
    dummy_images = torch.randn(64, 1, 28, 28)
    dummy_labels = torch.randint(0, 10, (64,))
    
    print("--- DUMMY DATA CREATED ---")
    print(f"Created a batch of {dummy_images.shape[0]} random images.\n")


    # --- THE TRAINING LOOP ---
    num_epochs = 5 # An "epoch" is one full pass over the entire dataset.

    # This is where the training iterations begin.
    for epoch in range(num_epochs):
        # ======================================================================
        # START OF A NEW ITERATION (EPOCH)
        # The model starts this iteration with the weights from the previous one.
        # ======================================================================
        print(f"\n--- Starting Epoch {epoch + 1}/{num_epochs} ---")

        # 1. Set the model to training mode
        model.train()

        # 2. Clear previous gradients
        optimizer.zero_grad()

        # 3. Forward pass: Feed the data through the model to get predictions
        outputs = model(dummy_images)

        # 4. Calculate the error (loss)
        loss = criterion(outputs, dummy_labels)
        print(f"Calculated Loss for this epoch: {loss.item():.4f}")

        # 5. Backward pass: Calculate how much each weight contributed to the error
        loss.backward()

        # ======================================================================
        # WEIGHTS ARE UPDATED HERE
        # The optimizer uses the calculated gradients to adjust the model's
        # weights directly in RAM. This is the core "learning" step.
        # ======================================================================
        optimizer.step()
        
        # ======================================================================
        # END OF THE ITERATION (EPOCH)
        # The model now has a new, slightly improved set of weights in memory,
        # ready for the next epoch.
        # ======================================================================
        
        # Let's look at the weights to see that they've changed
        weights_after_epoch = extract_weights_to_array(model)
        print(f"First 5 weights after epoch {epoch + 1}: {[round(w, 4) for w in weights_after_epoch[:5]]}")

    print("\n--- TRAINING COMPLETE ---")
    
    # --- FINAL STEP: GETTING THE WEIGHTS ---
    # After all training is done, your user module would call this function
    # to get the final weights array, which is then ready for the
    # cryptographic processing and submission to the server.
    final_trained_weights = extract_weights_to_array(model)
    
    print(f"\nFinal trained weights extracted into a single array.")
    print(f"This array is what your user module will process.")
    print(f"First 5 final weights: {[round(w, 4) for w in final_trained_weights[:5]]}")

