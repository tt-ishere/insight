#!/bin/bash
cd /opt/exceltool
/opt/exceltool/venv/bin/streamlit run app.py --server.port 8501 --server.address 0.0.0.0
