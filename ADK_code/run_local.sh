#!/bin/bash

# ==============================================================================
# Local Agent Runner Script (Auto-Setup Version)
# ==============================================================================
# This script sets up the environment and runs the ADK agent locally.
# It automatically creates the virtual environment and installs dependencies if missing.

# --- 1. Set the Working Directory ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Setting working directory to: $SCRIPT_DIR"
cd "$SCRIPT_DIR" || exit 1

# --- 2. Activate (or Create) Virtual Environment ---
if [ ! -f ".venv/bin/activate" ]; then
    echo "--- First Run Detected: Creating Virtual Environment ---"
    python3 -m venv .venv
fi

source .venv/bin/activate
echo "Virtual environment activated."

# --- 3. Check & Install Dependencies ---
# We check for a key package (google-adk) to see if we need to install libs.
if ! python -c "import google.adk" &> /dev/null; then
    echo "--- Installing Dependencies (This may take a minute) ---"
    pip install --upgrade pip
    pip install "google-adk>=1.15.1" \
        "google-cloud-aiplatform[adk,agent_engines]>=1.119.0" \
        google-cloud-pubsub \
        google-genai \
        google-cloud-logging \
        google-cloud-bigquery \
        google-cloud-storage \
        db-dtypes \
        pandas \
        cloudpickle \
        pydantic \
        python-dotenv
    echo "--- Dependencies Installed ---"
fi

# --- 4. Configure Python's Module Search Path ---
export PYTHONPATH="$SCRIPT_DIR"

# --- UNIQUE PROJECT CONFIGURATION DETAILS BELOW ---
export GOOGLE_CLOUD_PROJECT="bigquery-demos-project"
export GOOGLE_CLOUD_LOCATION="us-central1"
# --- UNIQUE PROJECT CONFIGURATION DETAILS ABOVE ---

export GOOGLE_GENAI_USE_VERTEXAI=1

# --- 5. Run the Application ---
echo "Starting Agent Runner..."
echo "---------------------------------------------------"
python -m agent_runner
