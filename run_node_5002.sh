#!/bin/bash
# Menjalankan node Rumah Sakit B di port 5002
export NODE_ID=RS_B
export NODE_PORT=5002
export DOCTOR_ID=dokter_RS_B
export PEERS=http://localhost:5001

python3 -m uvicorn network.node_api:app --reload --port "$NODE_PORT"
