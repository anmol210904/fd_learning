from flask import Flask, request, jsonify
from globalVariables import global_values
from aggrigaator_logic import aggrigatorInstance
import threading
import digitalSignature
import base64

# Initialize the Flask application
app = Flask(__name__)


@app.route('/registerUser', methods=['POST'])
def register_user():
    """
    This endpoint handles user registration by accepting a signed Diffie-Hellman public key.
    """
    if(global_values.window != 1):
        return jsonify({'error': 'Wrong Window'}), 400

    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400

    data = request.get_json()

    # Check for all required fields in the JSON data
    required_fields = ['publicKey', 'signature', 'DSAPK']
    if not all(field in data for field in required_fields):
        return jsonify({'error': f'Missing one or more required fields: {required_fields}'}), 400

    # Get the Base64 encoded strings from the request
    public_key_b64 = data['publicKey']
    signature_b64 = data['signature']
    dsapk_b64 = data["DSAPK"]

    # --- FIX: DECODE ALL BASE64 STRINGS BACK INTO BYTES ---
    # The client encoded the bytes into text for transport; we must decode them back to bytes.
    try:
        # The message that was signed is the user's Diffie-Hellman public key
        message_bytes = base64.b64decode(public_key_b64)
        
        # The signature of that message
        signature_bytes = base64.b64decode(signature_b64)
        
        # The user's DSA public key, which is needed to perform the verification
        dsapk_bytes = base64.b64decode(dsapk_b64)

    except (base64.binascii.Error, TypeError) as e:
        # This error occurs if the client sends a string that is not valid Base64
        return jsonify({'error': f'Invalid Base64 encoding in request: {e}'}), 400

    # --- Pass the correctly formatted BYTES to the verification function ---
    if digitalSignature.SignatureHandler.verify_signature(
        public_key_bytes=dsapk_bytes,
        message=message_bytes,
        signature=signature_bytes
    ):
        
        # If the signature is valid, send back the server's information


        # this token will itself contain its signed value to get varified.
        token = aggrigatorInstance.registerUser(message_bytes,signature_bytes,dsapk_bytes) 

        

        return jsonify({
            'userToken': token
        }), 200
    else:
        # If the signature does not match the message and key, reject the request
        return jsonify({'error': 'Invalid Signature'}), 400

 

#user fetching other users keys etc
@app.route('/getUser/<int:token>', methods=['GET'])
def get_users(token):
    """
    This endpoint retrieves user information based on a token.
    The token is expected as an integer in the URL path.
    """

    if(global_values.window != 2):
        return jsonify({'error': 'Wrong Window'}), 400

    
    try:
        if not isinstance(token, int):
            return jsonify({'error': 'Token must be an integer'}), 400

        try:
            users = aggrigatorInstance.getUsersPk()
        except Exception as e:
            return jsonify({'error': f'Failed to fetch users: {str(e)}'}), 500

        users_json = []
        for u in users:
            try:
                users_json.append({
                    'public_key': base64.b64encode(u.PK).decode('utf-8'),
                    'signature': base64.b64encode(u.SignedPK).decode('utf-8'),
                    'DSA_public_key': base64.b64encode(u.DSAPK).decode('utf-8')
                })


            except Exception as e:
                return jsonify({'error': f'Failed to encode user object: {str(e)}'}), 500

        return jsonify({'users': users_json}), 200

    except Exception as e:
        return jsonify({'error': f'Unexpected server error: {str(e)}'}), 500






#in this we will get a list of bi every user want to share with other user
@app.route('/submit_shamir_shares', methods=['POST'])
def submit_shamir_shares():
    """
    This endpoint receives a package of encrypted Shamir's shares from a user.
    The user must provide their session token for authentication.
    """
    # --- 1. Validate the incoming request ---
    if(global_values.window != 3):
        return jsonify({'error': 'Wrong Window'}), 400

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request. Missing JSON payload."}), 400

        token = data.get('token')
        shares_list = data.get('shares')

        # Check for presence and correct types
        if token is None or not isinstance(token, int):
            return jsonify({"error": "Invalid or missing 'token'. Must be an integer."}), 400
        
        if shares_list is None or not isinstance(shares_list, list):
            return jsonify({"error": "Invalid or missing 'shares'. Must be a list."}), 400
        
        if not all(isinstance(s, str) for s in shares_list):
            return jsonify({"error": "All items in 'shares' must be strings (Base64 encoded)."}), 400

    except Exception:
        return jsonify({"error": "Malformed JSON in request body."}), 400

    # --- 2. Process the data (Placeholder) ---
    # At this point, the input is validated.
    # In a real application, you would now process these shares.
    # For example, you would store them to be delivered to the other users.
    
    # shares_list



    # Store the shares in our placeholder data store
    # server_data_store[token] = shares_list
    
    aggrigatorInstance.populateMaskSharesMatrix(shares_list,token)
    # --- 3. Send a success response ---
    return jsonify({
        "message": "Shares received successfully."
    }), 200


@app.route('/get_shamir_shares', methods=['POST'])
def get_shamir_shares():
    """
    This endpoint retrieves all the Shamir's shares for a specific user.
    The user identifies themselves using their session token.
    """
    if(global_values.window != 4):
        return jsonify({'error': 'Wrong Window'}), 400

    # --- 1. Validate the incoming request ---
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request. Missing JSON payload."}), 400

        token = data.get('token')

        # Check for presence and correct type (must be a positive integer)
        if token is None or not isinstance(token, int) or token <= 0:
            return jsonify({"error": "Invalid or missing 'token'. Must be a positive integer."}), 400

    except Exception:
        return jsonify({"error": "Malformed JSON in request body."}), 400

    # --- 2. Retrieve the shares using your aggregator instance ---
    # This calls the method from your existing class to get the column data
    user_shares = aggrigatorInstance.get_shmair_shares_for_user(token)

    # You might want to handle the case where the user has no shares yet
    if not user_shares:
        return jsonify({
            "message": "No shares found for this user yet.",
            "shares": []
        }), 200

    # --- 3. Return the shares to the user ---
    return jsonify({
        "message": "Shares retrieved successfully.",
        "shares": user_shares
    }), 200




@app.route('/submit_data', methods=['POST'])
def submit_data():
    """
    Receives a user's masked weights and verification tag for a round.
    """
    if(global_values.window != 5):
        return jsonify({'error': 'Wrong Window'}), 400

    try:
        # --- 1. Get and Validate Data ---
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON payload."}), 400

        token = data.get('token')
        masked_weights = data.get('masked_weights')
        verification_tags = data.get('verification_tags')

        # Validate token
        if token is None or not isinstance(token, int):
            return jsonify({"error": "Invalid or missing 'token'. Must be an integer."}), 400

        # Validate masked_weights
        if masked_weights is None or not isinstance(masked_weights, list):
            return jsonify({"error": "Invalid or missing 'masked_weights'. Must be a list."}), 400

        # Validate verification_tags
        if verification_tags is None or not isinstance(verification_tags, list):
            return jsonify({"error": "Invalid or missing 'verification_tags'. Must be a list."}), 400

        # --- 2. Process and Store Data (Placeholder) ---
        # In your real application, you would call your aggregator instance here.
        # aggregator.receive_masked_weights(masked_weights, token)
        # aggregator.receive_verification_tag(verification_tags, token)
        
        aggrigatorInstance.receive_masked_weights(masked_weights,token)
        aggrigatorInstance.receive_verification_tag( verification_tags,token)

        # --- 3. Send Success Response ---
        return jsonify({
            "message": "Data received successfully.",
            "token": token
        }), 200

    except Exception as e:
        # General error handler
        return jsonify({"error": f"An internal server error occurred: {str(e)}"}), 500
    





@app.route('/submit_summed_shares', methods=['POST'])
def submit_summed_shares():
    """
    Receives a user's summed shares vector (b_sum,i) for a round.
    """
    if(global_values.window != 5):
        return jsonify({'error': 'Wrong Window'}), 400

    try:
        # --- 1. Get and Validate Data ---
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON payload."}), 400

        token = data.get('token')
        summed_shares = data.get('summed_shares')

        # Validate token
        if token is None or not isinstance(token, int):
            return jsonify({"error": "Invalid or missing 'token'. Must be an integer."}), 400

        # Validate summed_shares
        if summed_shares is None or not isinstance(summed_shares, list):
            return jsonify({"error": "Invalid or missing 'summed_shares'. Must be a list."}), 400

        # --- 2. Process and Store Data ---
        # In your real application, you would call the corresponding method
        # on your aggregator instance.
        # aggrigatorInstance.receive_summed_shares(summed_shares, token)
        
        aggrigatorInstance.receive_summed_shares(summed_shares,token)

        # --- 3. Send Success Response ---
        return jsonify({
            "message": "Summed shares received successfully.",
            "token": token
        }), 200

    except Exception as e:
        # General error handler
        return jsonify({"error": f"An internal server error occurred: {str(e)}"}), 500



@app.route('/get_global_model', methods=['GET'])
def get_global_model():
    """
    Allows a user to retrieve the final global model for the current round.
    This uses a long-polling approach: it will wait until the model is ready.
    """

    if(global_values.window != 6):
        print("window = ",global_values.window)
        return jsonify({'error': f'Wrong Window'}), 400

    try:
        # In a real system, you might add a timeout to this loop.
        # For now, it will wait until the aggregator's main loop computes the model.

        global_model = aggrigatorInstance.get_global_model()
        aggrigated_tag = aggrigatorInstance.get_aggrigated_tag()

        print(aggrigated_tag)
        
        return jsonify({
            "message": "Global model is ready.",
            "global_model_weights": global_model,
            "aggrigated_tag":aggrigated_tag
        }), 200

    except Exception as e:
        # General error handler
        return jsonify({"error": f"An internal server error occurred: {str(e)}"}), 500
    

@app.route('/get_initial_model', methods=['GET'])
def get_initial_model():
    """
    Allows a user to retrieve the final global model for the current round.
    This uses a long-polling approach: it will wait until the model is ready.
    """

    if(global_values.window != 0):
        print("window = ",global_values.window)
        return jsonify({'error': 'Wrong Window'}), 400

    try:
        # In a real system, you might add a timeout to this loop.
        # For now, it will wait until the aggregator's main loop computes the model.

        global_model = aggrigatorInstance.get_global_model()

        
        
        return jsonify({
            "message": "Global model is ready.",
            "global_model_weights": global_model,
            "aggrigated_tag":global_model
        }), 200

    except Exception as e:
        # General error handler
        return jsonify({"error": f"An internal server error occurred: {str(e)}"}), 500




def run_flask_app():
    """Function to run the Flask server."""
    print("Starting Flask server in a separate thread...")
    # Note: Werkzeug reloader should be disabled when running in this manner.
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)






if __name__ == "__main__" :
    print("The main script started")

    flask_thread = threading.Thread(target=run_flask_app, daemon=True)

    # Start the thread
    flask_thread.start()
    
    aggrigatorInstance.mainfunction()


    