# 🚀 PhantomCortex - Quick Start Guide

Get up and running in 5 minutes!

## ⚡ Fast Installation

```bash
# 1. Clone repository
git clone https://github.com/yourusername/PhantomCortex.git
cd PhantomCortex

# 2. Setup environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. Download translation model
python scripts/setup_translation.py

# 4. Configure
cp config/config.example.yaml config/config.yaml
nano config/config.yaml  # Edit email settings

# 5. Test
python core/collector.py --test
```

## 📧 Minimum Configuration

Edit `config/config.yaml`:

```yaml
email:
  smtp:
    server: smtp.gmail.com
    port: 587
    username: your-email@gmail.com
    password: ""  # Set via: export PHANTOMCORTEX_EMAIL_PASSWORD="xxx"
    
  to_addresses:
    - your-email@gmail.com
```

## 🎯 First Run

```bash
# Collect threats
python core/collector.py

# View results
cat data/daily_threats.json | python -m json.tool | head -50

# Send alert (if threats found)
python modules/alerting.py
```

## 📅 Automate (Linux/Mac)

```bash
# Edit crontab
crontab -e

# Add daily collection at 8 AM
0 8 * * * cd /path/to/PhantomCortex && ./scripts/run_daily.sh
```

## 🆘 Troubleshooting

### Translation not working?
```bash
python scripts/setup_translation.py --test
```

### Email not sending?
```bash
# Check SMTP settings
python scripts/test_email.py

# For Gmail: Use App Password, not regular password
# https://myaccount.google.com/apppasswords
```

### No threats collected?
```bash
# Run in debug mode
python core/collector.py --debug

# Check if your technologies are configured
cat config/technologies.yaml
```

## 📚 Next Steps

1. **Customize**: See [docs/CUSTOMIZATION.md](docs/CUSTOMIZATION.md)
2. **Add Sources**: Edit `config/sources.yaml`
3. **Schedule**: See [docs/INSTALLATION.md](docs/INSTALLATION.md#scheduling-automation)
4. **Learn More**: Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## 🎉 That's it!

You now have a working threat intelligence platform.

**Need help?** Check [docs/](docs/) or open an [issue](https://github.com/yourusername/PhantomCortex/issues).
