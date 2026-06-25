#!/bin/bash
export FASKES_ID=RS_B
export PEERS=http://localhost:5001
python3 -m uvicorn network.node_api:create_app --factory --reload --port 5002