#!/bin/bash
# Menjalankan node Rumah Sakit A di port 5001
export NODE_ID=RS_A
export NODE_PORT=5001
export DOCTOR_ID=dokter_RS_A
export PEERS=http://localhost:5002

python3 -m uvicorn network.node_api:app --reload --port "$NODE_PORT"
