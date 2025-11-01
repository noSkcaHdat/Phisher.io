Clone the repo and replace your Virus total api key 
Then follow below steps
# Four-Model Phishing Detector

## Run backend
```bash
cd backend
python -m venv .venv && . .venv/bin/activate  #for windows
pip install -r requirements.txt
cp .env.example .env   # change your VT apikey here
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Run frontend
```bash
cd frontend
cp .env.example .env   # VITE_API_BASE defaults to http://localhost:8000
npm i
npm run dev
```

## Tests
- Backend: `cd backend && pytest -q`
- Frontend: `cd frontend && npm run test`
