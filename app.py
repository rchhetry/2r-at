from flask import Flask, request, jsonify
import subprocess
import json
import os
import tempfile
import shlex # For safe command construction

app = Flask(__name__)

# THIS IS A PLACEHOLDER - REPLACE WITH YOUR ACTUAL AUTH MECHANISM
def is_authenticated(request_obj):
    # Example: Check for a session cookie or a valid API token
    # return request_obj.cookies.get('session_id') is not None
    # For now, assume authenticated for conceptual purposes, but STRESS this needs real implementation
    return True

@app.route('/api/nuclei/scan', methods=['POST'])
def nuclei_scan():
    if not is_authenticated(request): # Your actual authentication check
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    if not data or 'hostname' not in data:
        return jsonify({"error": "Hostname is required"}), 400

    hostname = data['hostname']

    # Basic validation for hostname (you might need more robust validation)
    if not (hostname.replace('.', '').isalnum()): # Very basic check
        return jsonify({"error": "Invalid hostname format"}), 400

    # Secure temporary file for Nuclei output
    try:
        # Create a temporary file to store Nuclei's JSON output
        temp_output_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json')
        temp_output_path = temp_output_file.name
        temp_output_file.close() # Close it so Nuclei can write to it

        # Construct the Nuclei command securely
        # Replace 'nuclei' with the full path if necessary
        # Add any other Nuclei flags you need, e.g., -silent, -t specific_templates
        nuclei_command = [
            'nuclei',
            '-u', hostname,
            '-json', # Output in JSON format
            '-o', temp_output_path, # Output to the temporary file
            '-silent' # Suppress progress bar and other noisy output
        ]

        # For safety, you might want to add specific templates or exclude dangerous ones
        # nuclei_command.extend(['-t', 'cnvd,http'])


        # Execute the command
        # Set a timeout (e.g., 5 minutes = 300 seconds)
        timeout_seconds = 300
        process = subprocess.Popen(nuclei_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=timeout_seconds)

        if process.returncode != 0:
            # If Nuclei exits with an error
            error_message = f"Nuclei scan failed. Return code: {process.returncode}"
            if stderr:
                error_message += f" Error: {stderr.decode('utf-8', errors='ignore')}"
            # Consider logging stderr for debugging
            return jsonify({"error": error_message, "details": stderr.decode('utf-8', errors='ignore')}), 500

        # Read the JSON output from the temporary file
        with open(temp_output_path, 'r') as f:
            results = json.load(f)

        return jsonify(results), 200

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Nuclei scan timed out"}), 504 # Gateway Timeout
    except FileNotFoundError:
        # This means the nuclei command itself was not found
        return jsonify({"error": "Nuclei command not found. Ensure it is installed and in PATH."}), 500
    except json.JSONDecodeError:
        # This means Nuclei ran but output was not valid JSON
        return jsonify({"error": "Failed to parse Nuclei output. The output file might be empty or malformed."}), 500
    except Exception as e:
        # General error
        # Log the error: app.logger.error(f"Nuclei scan error: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        # Clean up the temporary file
        if 'temp_output_path' in locals() and os.path.exists(temp_output_path):
            os.remove(temp_output_path)

if __name__ == '__main__':
    # This is for local testing of the Flask app.
    # Your actual Apache/RedHat setup will use a WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, port=5000)
