# 1) البيئة والاعتمادات
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git

# 2) مجلد مشروع ببيئة معزولة (يمنع تعارض حزم كالي)
mkdir ~/osint-framework && cd ~/osint-framework
python3 -m venv venv
source venv/bin/activate

# 3) التبعيات
pip3 install aiohttp dnspython playwright
playwright install chromium      # متصفح اللقطات (~150MB)

# 4) حفظ الكود
nano osint_orchestrator.py       # الصق الكود الموحّد واحفظ (Ctrl+O ثم Ctrl+X)

# 5) مفاتيح API الاختيارية (بدونها يعمل الإطار بالمصادر المجانية)
export GITHUB_TOKEN="ghp_xxxx"   # github.com → Settings → Developer settings → PAT
export SHODAN_API_KEY="xxxx"     # shodan.io
# لجعلها دائمة: أضفها في ~/.bashrc

# 6) التشغيل
python3 osint_orchestrator.py -t example.com -c 50 \
    -w /usr/share/wordlists/dnsrecon/namelist.txt
