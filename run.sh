#!/usr/bin/env bash
# Start the Vantage server and guarantee port 5002 is freed on exit.
# Usage: ./run.sh

PORT=5002

# Kill anything already squatting on the port
lsof -ti :$PORT | xargs kill -9 2>/dev/null || true

# Activate venv if not already active
if [ -z "$VIRTUAL_ENV" ] && [ -f ".venv/bin/activate" ]; then
  source .venv/bin/activate
fi

# Trap Ctrl+C, kill, and normal exit — all free the port
cleanup() {
  echo ""
  echo "Stopping server on port $PORT..."
  kill "$FLASK_PID" 2>/dev/null
  wait "$FLASK_PID" 2>/dev/null
  lsof -ti :$PORT | xargs kill -9 2>/dev/null || true
}
trap cleanup INT TERM EXIT

python app.py &
FLASK_PID=$!
echo "Server PID $FLASK_PID running on http://localhost:$PORT"
echo "Press Ctrl+C to stop."
wait $FLASK_PID
