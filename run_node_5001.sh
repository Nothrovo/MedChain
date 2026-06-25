#!/bin/bash
export FASKES_ID=RS_A
export PEERS=http://localhost:5002
python3 -m uvicorn network.node_api:create_app --factory --reload --port 5001
