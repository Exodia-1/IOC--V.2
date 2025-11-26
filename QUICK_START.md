# 🚀 Quick Start - Deploy in 5 Minutes!

## ✅ Your Project is Ready!

The error you were seeing (`ENOENT: no such file or directory, open '/vercel/path0/package.json'`) has been **FIXED**! 

The project structure is now correct for Vercel deployment.

---

## 📝 3 Simple Steps to Deploy

### 1️⃣ Push to GitHub (30 seconds)

```bash
cd /app
git add .
git commit -m "Ready for Vercel deployment"
git push origin main
```

> **Don't have a GitHub repo yet?** Create one first:
> 1. Go to https://github.com/new
> 2. Name it `soc-ioc-analyzer`
> 3. Create repository (don't initialize with README)
> 4. Then run:
> ```bash
> git remote add origin https://github.com/YOUR_USERNAME/soc-ioc-analyzer.git
> git push -u origin main
> ```

---

### 2️⃣ Deploy on Vercel (2 minutes)

1. **Visit:** https://vercel.com
2. **Sign in** with your GitHub account
3. **Click:** "Add New..." → "Project"
4. **Select** your `soc-ioc-analyzer` repository
5. **Before clicking Deploy:**
   - Scroll to "Environment Variables"
   - Add your API keys (see below)
6. **Click:** "Deploy"
7. **Wait** 2-3 minutes for build

---

### 3️⃣ Test Your Live Site (1 minute)

1. Vercel will give you a URL like: `https://your-project.vercel.app`
2. Visit it and test with an IOC:
   - Try IP: `8.8.8.8`
   - Try Domain: `example.com`
   - Try Email: `test@gmail.com`

---

## 🔑 API Keys (Optional but Recommended)

Add these in Vercel's "Environment Variables" section:

| Variable Name | Get Free Key From |
|---------------|-------------------|
| `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/api |
| `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/join-us |
| `URLSCAN_API_KEY` | https://urlscan.io/about/api/ |
| `ALIENVAULT_API_KEY` | https://otx.alienvault.com/api |
| `GREYNOISE_API_KEY` | https://www.greynoise.io/ |

**Don't have all keys?** No problem! The app will work with the keys you have. Other services (Shodan, IPInfo, WHOIS) don't require keys.

---

## 🎯 What Changed?

### ❌ Old Structure (Causing Error)
```
/app/
├── frontend/
│   └── package.json    ← Vercel couldn't find this!
└── backend/
```

### ✅ New Structure (Fixed!)
```
/app/
├── package.json        ← At root! Vercel finds it!
├── vercel.json         ← Configuration
├── api/                ← Backend
└── src/                ← Frontend
```

---

## 🆘 Need Help?

- **Detailed guide:** Read [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md)
- **Structure explanation:** Read [PROJECT_STRUCTURE.md](./PROJECT_STRUCTURE.md)
- **Deployment fails?** Check you pushed to GitHub first
- **No results?** Add API keys in Vercel settings

---

## ✨ You're Done!

That's it! Your SOC IOC Analyzer will be live on Vercel in minutes. 

**Next time you make changes:**
```bash
git add .
git commit -m "Updated features"
git push
```

Vercel will auto-deploy! 🎉
