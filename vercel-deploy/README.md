# SOC IOC Analyzer - Vercel Deployment

## Free Hosting on Vercel

This project is configured for **100% free** deployment on Vercel.

### Prerequisites
1. GitHub account
2. Vercel account (free at vercel.com)
3. Your API keys

### Deployment Steps

#### Step 1: Push to GitHub
```bash
# Create a new repo on GitHub, then:
git init
git add .
git commit -m "SOC IOC Analyzer"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/soc-ioc-analyzer.git
git push -u origin main
```

#### Step 2: Import to Vercel
1. Go to [vercel.com](https://vercel.com)
2. Click "Add New Project"
3. Import your GitHub repository
4. Vercel will auto-detect the configuration

#### Step 3: Add Environment Variables
In Vercel project settings, add these secrets:

| Name | Value |
|------|-------|
| `ABUSEIPDB_API_KEY` | Your AbuseIPDB key |
| `VIRUSTOTAL_API_KEY` | Your VirusTotal key |
| `URLSCAN_API_KEY` | Your URLScan key |
| `ALIENVAULT_API_KEY` | Your AlienVault OTX key |
| `GREYNOISE_API_KEY` | Your GreyNoise key |

#### Step 4: Deploy
Click "Deploy" - Vercel handles everything!

### Project Structure
```
/
├── api/
│   ├── index.py          # FastAPI serverless function
│   └── requirements.txt  # Python dependencies
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
├── vercel.json           # Vercel configuration
└── README.md
```

### Features
- React frontend (static build)
- Python FastAPI backend (serverless functions)
- No database required (stateless)
- 11 threat intelligence sources
- Email header analyzer
- Domain WHOIS with registration dates

### Free Tier Limits
- 100GB bandwidth/month
- Serverless function executions: 100,000/month
- Build minutes: 6,000/month

More than enough for personal/small team use!

### Local Development
```bash
# Install Vercel CLI
npm i -g vercel

# Run locally
vercel dev
```

### API Endpoints
- `POST /api/detect` - Detect IOC type
- `POST /api/analyze` - Analyze single IOC
- `POST /api/analyze/bulk` - Analyze multiple IOCs
- `POST /api/analyze/email-headers` - Analyze email headers
- `GET /api/health` - Health check
