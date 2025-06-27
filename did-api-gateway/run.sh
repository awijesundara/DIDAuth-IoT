#!/bin/bash
source venv/bin/activate
exec uvicorn did_vc_api:app --host 0.0.0.0 --port 8000 --reload
