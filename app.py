# -*- coding: utf-8 -*-
"""PC Doctor X v2 — فحص حقيقي لأجزاء الجهاز، اختبارات أداء وإجهاد، تحليل أعطال، تقارير محفوظة.
التشغيل:  python app.py   (يحتاج: pip install psutil)
فحص صامت مجدول:  python app.py --scan"""
import sys, os, re, json, time, socket, shutil, platform, threading, subprocess, webbrowser, datetime, html, secrets, hashlib, heapq, tempfile, collections
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
try:
    import psutil
except ImportError:
    sys.exit("pip install psutil")

APP, VER = "PC Doctor X", "2.0"
IS_WIN = sys.platform == "win32"
NOWIN = 0x08000000 if IS_WIN else 0
DATA = os.path.join(os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config"), "PCDoctorX", "reports")
LOGS = os.path.join(os.path.dirname(DATA), "logs")
SETF = os.path.join(os.path.dirname(DATA), "settings.json")
os.makedirs(DATA, exist_ok=True)
os.makedirs(LOGS, exist_ok=True)
TOKEN = secrets.token_hex(16)
ALLOWED, START, LAST_PING = set(), time.time(), [0]
ID_RE = re.compile(r"^\d{8}-\d{6}$")
PORT = [0]

# ---------------------------------------------------------------- helpers
def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def run(args, timeout=30):
    try:
        r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, creationflags=NOWIN)
        return r.stdout.strip()
    except Exception:
        return ""

def ps(cmd, timeout=40):
    if not IS_WIN:
        return ""
    return run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + cmd], timeout)

def psj(cmd, timeout=40):
    out = ps(cmd + " | ConvertTo-Json -Depth 3 -Compress", timeout)
    if not out:
        return []
    try:
        d = json.loads(out)
        return d if isinstance(d, list) else [d]
    except Exception:
        return []

def gb(b):
    return f"{b / 1024 ** 3:.1f} GB"

def dur(s):
    d, r = divmod(int(s), 86400)
    h, r = divmod(r, 3600)
    return (f"{d} يوم " if d else "") + f"{h} ساعة {r // 60} دقيقة"

def F(sev, text, fix=""):
    return {"sev": sev, "text": text, "fix": fix}

SEV = {"bad": 2, "warn": 1, "info": 0}

def mk(id_, title, icon, metrics, finds, na=False, data=None):
    w = max([SEV[f["sev"]] for f in finds] or [0])
    return {"id": id_, "title": title, "icon": icon, "status": "na" if na else ["ok", "warn", "bad"][w],
            "metrics": metrics, "findings": finds, "data": data or {}}

def old_date(s, years):
    try:
        return (datetime.date.today() - datetime.date.fromisoformat(s)).days > 365 * years
    except Exception:
        return False

def cpu_temp():
    try:
        s = psutil.sensors_temperatures()
        for k in ("coretemp", "k10temp", "cpu_thermal"):
            if s.get(k):
                return max(x.current for x in s[k])
    except Exception:
        pass
    if IS_WIN:
        o = ps("Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue"
               " | ForEach-Object {$_.CurrentTemperature}", 15)
        try:
            v = [int(x) / 10 - 273.15 for x in o.split()]
            v = [x for x in v if 10 < x < 120]
            return max(v) if v else None
        except Exception:
            return None
    return None

# ---------------------------------------------------------------- collectors
def c_system():
    m = {"اسم الجهاز": platform.node(), "النظام": platform.platform(), "مدة التشغيل": dur(time.time() - psutil.boot_time())}
    f = []
    if IS_WIN:
        cs = psj("Get-CimInstance Win32_ComputerSystem | Select Manufacturer,Model")
        bb = psj("Get-CimInstance Win32_BaseBoard | Select Manufacturer,Product")
        if cs:
            m["الموديل"] = f"{cs[0].get('Manufacturer', '')} {cs[0].get('Model', '')}".strip()
        if bb:
            m["اللوحة الأم"] = f"{bb[0].get('Manufacturer', '')} {bb[0].get('Product', '')}".strip()
    up = time.time() - psutil.boot_time()
    if up > 14 * 86400:
        f.append(F("warn", f"الجهاز شغّال منذ {int(up // 86400)} يوم بدون إعادة تشغيل",
                   "أعد تشغيل الجهاز لتطبيق التحديثات وتفريغ الذاكرة"))
    return mk("system", "معلومات النظام", "🖥️", m, f)

def c_cpu():
    per = psutil.cpu_percent(interval=1.5, percpu=True)
    avg = sum(per) / len(per)
    name = platform.processor()
    if IS_WIN:
        r = psj("Get-CimInstance Win32_Processor | Select Name")
        if r:
            name = str(r[0].get("Name", name)).strip()
    fr = psutil.cpu_freq()
    m = {"المعالج": name, "النوى / الخيوط": f"{psutil.cpu_count(False)} / {psutil.cpu_count()}", "الاستخدام": f"{avg:.0f}%"}
    if fr:
        m["السرعة"] = f"{fr.current:.0f} MHz"
    f = []
    if avg > 85:
        f.append(F("warn", f"استخدام المعالج مرتفع ({avg:.0f}%) أثناء الفحص", "أغلق البرامج الثقيلة وراجع مدير المهام"))
    t = cpu_temp()
    if t:
        m["الحرارة"] = f"{t:.0f}°C"
        if t >= 90:
            f.append(F("bad", f"حرارة عالية جداً ({t:.0f}°C)", "نظّف المراوح من الغبار وتأكد من التهوية وغيّر المعجون الحراري"))
        elif t >= 80:
            f.append(F("warn", f"حرارة مرتفعة ({t:.0f}°C)", "نظّف الغبار وحسّن التهوية"))
    else:
        f.append(F("info", "تعذّر قراءة حرارة المعالج (شغّل البرنامج كمسؤول أو قد لا يدعمها الجهاز)"))
    return mk("cpu", "المعالج", "🧠", m, f, data={"threads": psutil.cpu_count() or 1, "temp": t})

def c_ram():
    v, s = psutil.virtual_memory(), psutil.swap_memory()
    agg = {}
    for p in psutil.process_iter(["name", "memory_info"]):
        try:
            agg[p.info["name"] or "?"] = agg.get(p.info["name"] or "?", 0) + p.info["memory_info"].rss
        except Exception:
            pass
    top = sorted(agg.items(), key=lambda x: -x[1])[:5]
    m = {"الإجمالي": gb(v.total), "المستخدم": f"{gb(v.used)} ({v.percent:.0f}%)", "المتاح": gb(v.available),
         "ملف الصفحات": f"{s.percent:.0f}%", "أثقل البرامج": "، ".join(f"{n} ({gb(b)})" for n, b in top)}
    f = []
    if v.percent >= 90:
        f.append(F("bad", f"الذاكرة ممتلئة تقريباً ({v.percent:.0f}%)", "أغلق البرامج الثقيلة أو زوّد الرامات"))
    elif v.percent >= 80:
        f.append(F("warn", f"استخدام الذاكرة مرتفع ({v.percent:.0f}%)", "أغلق البرامج غير الضرورية أو فكّر في زيادة الرامات"))
    if v.total < 8 * 1024 ** 3:
        f.append(F("warn", f"حجم الذاكرة صغير ({gb(v.total)})", "8 جيجا هي الحد الأدنى المريح لويندوز 10 و11"))
    return mk("ram", "الذاكرة (RAM)", "🧩", m, f, data={"total": v.total, "pct": v.percent})

def c_disks():
    m, f, dd, phys = {}, [], [], []
    for p in psutil.disk_partitions(all=False):
        if "cdrom" in p.opts or not p.fstype:
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
        except Exception:
            continue
        m[f"المساحة {p.mountpoint}"] = f"{gb(u.used)} من {gb(u.total)} ({u.percent:.0f}%)"
        dd.append({"m": p.mountpoint, "used": u.used, "total": u.total, "pct": u.percent})
        if u.percent >= 95:
            f.append(F("bad", f"القرص {p.mountpoint} ممتلئ ({u.percent:.0f}%)", "احذف الملفات غير الضرورية أو انقلها لقرص آخر"))
        elif u.percent >= 90:
            f.append(F("warn", f"القرص {p.mountpoint} شبه ممتلئ ({u.percent:.0f}%)", "حرّر مساحة؛ الأفضل إبقاء 15% فارغة"))
    if IS_WIN:
        rc = {str(r.get("DeviceId")): r for r in psj(
            "Get-PhysicalDisk | Get-StorageReliabilityCounter | Select DeviceId,Temperature,Wear,ReadErrorsTotal,WriteErrorsTotal,PowerOnHours")}
        for d in psj("Get-PhysicalDisk | Select DeviceId,FriendlyName,MediaType,HealthStatus,OperationalStatus,Size"):
            name, typ, hs = d.get("FriendlyName", "?"), d.get("MediaType", "?"), str(d.get("HealthStatus", "?"))
            m[f"قرص: {name}"] = f"{typ} — الحالة: {hs}"
            if hs not in ("Healthy", "0"):
                f.append(F("bad", f"حالة القرص {name}: {hs}", "انسخ بياناتك المهمة فوراً وفكّر في استبدال القرص"))
            r = rc.get(str(d.get("DeviceId")), {})
            phys.append({"name": name, "type": str(typ), "wear": r.get("Wear"), "temp": r.get("Temperature")})
            if r.get("Temperature"):
                m[f"حرارة {name}"] = f"{r['Temperature']}°C"
                if r["Temperature"] >= 70:
                    f.append(F("warn", f"حرارة القرص {name} مرتفعة ({r['Temperature']}°C)", "حسّن التهوية داخل الجهاز"))
            if r.get("Wear") is not None:
                m[f"استهلاك {name}"] = f"{r['Wear']}%"
                if r["Wear"] >= 90:
                    f.append(F("bad", f"عمر القرص {name} شارف على الانتهاء ({r['Wear']}% استهلاك)", "استبدل القرص قريباً"))
                elif r["Wear"] >= 70:
                    f.append(F("warn", f"استهلاك القرص {name} {r['Wear']}%", "خذ نسخة احتياطية منتظمة"))
            errs = (r.get("ReadErrorsTotal") or 0) + (r.get("WriteErrorsTotal") or 0)
            if errs > 0:
                f.append(F("warn", f"القرص {name} سجّل {errs} أخطاء قراءة/كتابة", "راقب حالته وانسخ بياناتك احتياطياً"))
            if r.get("PowerOnHours"):
                m[f"ساعات تشغيل {name}"] = f"{r['PowerOnHours']} ساعة"
            if str(typ).upper() == "HDD":
                f.append(F("info", f"{name} هارد تقليدي (HDD)", "الترقية إلى SSD تسرّع الجهاز بشكل ملحوظ"))
    return mk("disks", "الأقراص والتخزين", "💾", m, f,
              data={"disks": dd, "phys": phys, "hdd": any(x["type"].upper() == "HDD" for x in phys)})

def c_gpu():
    m, f = {}, []
    for g in psj("Get-CimInstance Win32_VideoController | Select Name,DriverVersion,Status,"
                 "@{n='D';e={if($_.DriverDate){$_.DriverDate.ToString('yyyy-MM-dd')}}}"):
        n = g.get("Name", "?")
        m[n] = f"درايفر {g.get('DriverVersion', '?')} ({g.get('D', '?')})"
        if str(g.get("Status", "OK")) != "OK":
            f.append(F("warn", f"حالة كارت الشاشة {n}: {g.get('Status')}", "حدّث الدرايفر أو أعد تثبيته"))
        if g.get("D") and old_date(g["D"], 2):
            f.append(F("warn", f"درايفر {n} قديم (إصدار {g['D']})", "حمّل أحدث درايفر من موقع الشركة المصنّعة"))
    if shutil.which("nvidia-smi"):
        o = run(["nvidia-smi", "--query-gpu=temperature.gpu,utilization.gpu,memory.used,memory.total", "--format=csv,noheader,nounits"], 10)
        try:
            t, u, mu, mt = [int(x) for x in o.splitlines()[0].split(",")]
            m["حرارة الكارت"], m["الاستخدام"], m["VRAM"] = f"{t}°C", f"{u}%", f"{mu} / {mt} MB"
            if t >= 85:
                f.append(F("bad", f"حرارة كارت الشاشة عالية ({t}°C)", "نظّف المراوح وحسّن التهوية"))
            elif t >= 80:
                f.append(F("warn", f"حرارة كارت الشاشة مرتفعة ({t}°C)", "حسّن التهوية"))
        except Exception:
            pass
    if not m:
        return mk("gpu", "كارت الشاشة", "🎮", {"الحالة": "تعذّر قراءة بيانات كارت الشاشة"}, [], na=True)
    return mk("gpu", "كارت الشاشة", "🎮", m, f)

def c_drivers():
    if not IS_WIN:
        return mk("drivers", "الدرايفرات", "🔧", {"الحالة": "متاح على ويندوز فقط"}, [], na=True)
    m, f = {}, []
    bad = psj("Get-CimInstance Win32_PnPEntity | Where-Object {$_.ConfigManagerErrorCode -ne 0} | Select Name,ConfigManagerErrorCode")
    m["أجهزة بها مشاكل"] = len(bad)
    for d in bad[:8]:
        f.append(F("warn", f"جهاز به مشكلة: {d.get('Name') or 'غير معروف'} (كود {d.get('ConfigManagerErrorCode')})",
                   "افتح إدارة الأجهزة وحدّث الدرايفر أو أعد تثبيته"))
    old = [d for d in psj("Get-CimInstance Win32_PnPSignedDriver | Where-Object {$_.DeviceClass -in 'DISPLAY','NET','MEDIA','BLUETOOTH'} | "
                          "Select DeviceName,@{n='D';e={if($_.DriverDate){$_.DriverDate.ToString('yyyy-MM-dd')}}}")
           if d.get("D") and old_date(d["D"], 3)]
    m["درايفرات أقدم من 3 سنوات"] = len(old)
    if old:
        f.append(F("warn", f"{len(old)} درايفر قديم، منها: " + "، ".join(str(d.get("DeviceName")) for d in old[:3]),
                   "حدّثها من Windows Update أو موقع الشركة المصنّعة"))
    return mk("drivers", "الدرايفرات", "🔧", m, f)

def c_security():
    if not IS_WIN:
        return mk("security", "الأمان", "🛡️", {"الحالة": "متاح على ويندوز فقط"}, [], na=True)
    m, f = {}, []
    d = psj("Get-MpComputerStatus | Select AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge")
    if d:
        d = d[0]
        m["مضاد الفيروسات"] = "يعمل" if d.get("AntivirusEnabled") else "متوقف"
        m["الحماية اللحظية"] = "مفعّلة" if d.get("RealTimeProtectionEnabled") else "متوقفة"
        m["عمر تعريفات الفيروسات"] = f"{d.get('AntivirusSignatureAge')} يوم"
        if not d.get("AntivirusEnabled") or not d.get("RealTimeProtectionEnabled"):
            f.append(F("bad", "الحماية اللحظية من الفيروسات غير مفعّلة", "فعّل Windows Security أو برنامج حماية موثوق"))
        if (d.get("AntivirusSignatureAge") or 0) > 7:
            f.append(F("warn", "تعريفات مضاد الفيروسات قديمة", "حدّث تعريفات الحماية من Windows Update"))
    else:
        m["مضاد الفيروسات"] = "تعذّر قراءة حالة Defender (ربما يوجد برنامج حماية آخر)"
    for p in psj("Get-NetFirewallProfile | Select Name,Enabled"):
        on = p.get("Enabled") in (True, 1, "True")
        m[f"جدار الحماية ({p.get('Name')})"] = "مفعّل" if on else "متوقف"
        if p.get("Enabled") in (False, 0, "False"):
            f.append(F("warn", f"جدار الحماية متوقف في ملف {p.get('Name')}", "فعّله من Windows Security"))
    return mk("security", "الأمان", "🛡️", m, f)

def c_startup():
    if not IS_WIN:
        return mk("startup", "برامج الإقلاع", "🚀", {"الحالة": "متاح على ويندوز فقط"}, [], na=True)
    s = psj("Get-CimInstance Win32_StartupCommand | Select Name,Command")
    names = sorted({str(x.get("Name")) for x in s})
    m = {"عدد البرامج": len(names), "البرامج": "، ".join(names[:12]) or "—"}
    f = []
    bt = psj("Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational';Id=100} -MaxEvents 3 "
             "-ErrorAction SilentlyContinue | ForEach-Object { $x=[xml]$_.ToXml(); $b=($x.Event.EventData.Data | Where-Object {$_.Name -eq 'BootTime'}).'#text'; "
             "[pscustomobject]@{T=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm');Ms=[int]$b} }")
    if bt and bt[0].get("Ms"):
        sec = bt[0]["Ms"] / 1000
        m["آخر وقت إقلاع"] = f"{sec:.0f} ثانية"
        if sec > 90:
            f.append(F("warn", f"الجهاز احتاج {sec:.0f} ثانية للإقلاع", "عطّل برامج الإقلاع الثقيلة أو انقل ويندوز إلى SSD"))
    if len(names) > 15:
        f.append(F("warn", f"{len(names)} برنامج يعمل مع بدء التشغيل", "عطّل غير الضروري من مدير المهام ← Startup"))
    elif len(names) > 8:
        f.append(F("info", f"{len(names)} برنامج يعمل مع بدء التشغيل", "عطّل ما لا تحتاجه لتسريع الإقلاع"))
    return mk("startup", "برامج الإقلاع", "🚀", m, f, data={"count": len(names)})

def tcp_ms(host, n=3):
    r = []
    for _ in range(n):
        t = time.time()
        try:
            socket.create_connection((host, 53), timeout=2).close()
            r.append((time.time() - t) * 1000)
        except Exception:
            pass
    return r

def c_network():
    up = [n for n, s in psutil.net_if_stats().items() if s.isup and not n.lower().startswith(("lo", "loopback"))]
    m, f = {"الواجهات النشطة": "، ".join(up) or "لا يوجد"}, []
    lat = tcp_ms("1.1.1.1") + tcp_ms("8.8.8.8")
    if not lat:
        m["الإنترنت"] = "لا يوجد اتصال"
        f.append(F("bad", "لا يوجد اتصال بالإنترنت", "افحص الراوتر والكابل أو إعدادات الشبكة"))
    else:
        a = sum(lat) / len(lat)
        m["زمن الاستجابة"] = f"{a:.0f} ms"
        m["فقدان الاتصال"] = f"{(6 - len(lat)) * 100 // 6}%"
        if a > 150:
            f.append(F("warn", f"زمن استجابة الشبكة مرتفع ({a:.0f} ms)", "أعد تشغيل الراوتر أو اقترب منه أو استخدم كابل"))
        if len(lat) < 6:
            f.append(F("warn", "الاتصال غير مستقر (فشلت بعض المحاولات)", "افحص الراوتر ومزوّد الخدمة"))
    return mk("network", "الشبكة", "🌐", m, f)

def c_battery():
    b = psutil.sensors_battery()
    if b is None:
        return mk("battery", "البطارية", "🔋", {"الحالة": "لا توجد بطارية (جهاز مكتبي)"}, [], na=True)
    m = {"الشحن": f"{b.percent:.0f}%", "الطاقة": "موصول بالشاحن" if b.power_plugged else "على البطارية"}
    f, wear = [], None
    if IS_WIN:
        tmp = os.path.join(os.environ.get("TEMP", "."), "pcdx_batt.xml")
        run(["powercfg", "/batteryreport", "/xml", "/output", tmp], 30)
        try:
            x = open(tmp, encoding="utf-8", errors="ignore").read()
            d = int(re.search(r"<DesignCapacity>(\d+)", x).group(1))
            c = int(re.search(r"<FullChargeCapacity>(\d+)", x).group(1))
            w = max(0, 100 - c * 100 // d)
            wear = w
            m["صحة البطارية"] = f"{100 - w}% من السعة الأصلية"
            if w >= 50:
                f.append(F("bad", f"البطارية استُهلكت {w}% من سعتها", "فكّر في استبدال البطارية"))
            elif w >= 30:
                f.append(F("warn", f"البطارية فقدت {w}% من سعتها", "قلّل الشحن الكامل المتكرر"))
        except Exception:
            pass
    return mk("battery", "البطارية", "🔋", m, f, data={"wear": wear})

# ---------------------------------------------------------------- تحليل الأعطال
BUGS = {0x0A: ("IRQL_NOT_LESS_OR_EQUAL", "درايفر معطوب أو رامات تالفة"), 0x1A: ("MEMORY_MANAGEMENT", "رامات تالفة أو مشكلة درايفرات"),
        0x1E: ("KMODE_EXCEPTION_NOT_HANDLED", "درايفر أو برنامج حماية متعارض"), 0x24: ("NTFS_FILE_SYSTEM", "تلف في القرص أو نظام الملفات"),
        0x3B: ("SYSTEM_SERVICE_EXCEPTION", "درايفر (غالباً الشاشة أو الحماية)"), 0x4E: ("PFN_LIST_CORRUPT", "رامات تالفة"),
        0x50: ("PAGE_FAULT_IN_NONPAGED_AREA", "رامات أو درايفر أو قرص"), 0x77: ("KERNEL_STACK_INPAGE_ERROR", "مشكلة في القرص أو الكابل"),
        0x7A: ("KERNEL_DATA_INPAGE_ERROR", "القرص أو الكابل أو الرامات"), 0x7B: ("INACCESSIBLE_BOOT_DEVICE", "القرص أو وضع SATA/AHCI"),
        0x7E: ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "درايفر قديم"), 0x7F: ("UNEXPECTED_KERNEL_MODE_TRAP", "عتاد (رامات/حرارة/معالج)"),
        0x9F: ("DRIVER_POWER_STATE_FAILURE", "درايفر أو إعدادات الطاقة"), 0xC2: ("BAD_POOL_CALLER", "درايفر معطوب"),
        0xD1: ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "درايفر (غالباً الشبكة)"), 0xEF: ("CRITICAL_PROCESS_DIED", "تلف ملفات النظام أو القرص"),
        0xF4: ("CRITICAL_OBJECT_TERMINATION", "القرص أو الكابل"), 0x101: ("CLOCK_WATCHDOG_TIMEOUT", "المعالج أو حرارته"),
        0x116: ("VIDEO_TDR_FAILURE", "درايفر كارت الشاشة أو حرارته"), 0x117: ("VIDEO_TDR_TIMEOUT_DETECTED", "درايفر كارت الشاشة"),
        0x124: ("WHEA_UNCORRECTABLE_ERROR", "عتاد (معالج/رامات/باور/حرارة)"), 0x133: ("DPC_WATCHDOG_VIOLATION", "درايفر أو فيرموير SSD"),
        0x139: ("KERNEL_SECURITY_CHECK_FAILURE", "درايفر أو رامات"), 0x154: ("UNEXPECTED_STORE_EXCEPTION", "SSD أو القرص")}

def ev(filt, extra="", days=7):
    return psj("Get-WinEvent -FilterHashtable @{" + filt + ";StartTime=(Get-Date).AddDays(-%d)} -ErrorAction SilentlyContinue | "
               "Select @{n='T';e={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm')}}%s" % (days, extra), 60)

def c_crashes(days=7):
    if not IS_WIN:
        return mk("crashes", "تحليل الأعطال", "💥", {"الحالة": "متاح على ويندوز فقط"}, [], na=True)
    bs = ev("LogName='System';Id=1001;ProviderName='Microsoft-Windows-WER-SystemErrorReporting'", ",Message", days)
    kp = ev("LogName='System';Id=41;ProviderName='Microsoft-Windows-Kernel-Power'", "", days)
    ap = ev("LogName='Application';Id=1000;ProviderName='Application Error'", ",@{n='App';e={$_.Properties[0].Value}}", days)
    wh = ev("LogName='System';ProviderName='Microsoft-Windows-WHEA-Logger'", "", days)
    dk = ev("LogName='System';Id=7,11,51;ProviderName='disk'", "", days)
    events, f = [], []
    for b in bs:
        mt = re.search(r"0x([0-9a-fA-F]{8})", b.get("Message") or "")
        code = int(mt.group(1), 16) if mt else None
        nm, why = BUGS.get(code, ("غير معروف", "افحص الدرايفرات والرامات والقرص")) if code is not None else ("غير معروف", "")
        events.append({"t": b.get("T"), "kind": "شاشة زرقاء", "info": (f"0x{code:X} {nm} — " if code is not None else "") + f"السبب المحتمل: {why}"})
        if code is not None:
            b["code"], b["why"], b["nm"] = code, why, nm
    for k in kp:
        events.append({"t": k.get("T"), "kind": "إيقاف مفاجئ", "info": "الجهاز أُغلق بدون إيقاف تشغيل سليم (Kernel-Power 41)"})
    for w in wh:
        events.append({"t": w.get("T"), "kind": "خطأ عتاد", "info": "WHEA-Logger: خطأ في العتاد (معالج/رامات/ناقل)"})
    for d in dk:
        events.append({"t": d.get("T"), "kind": "خطأ قرص", "info": "حدث خطأ في القرص (disk 7/11/51)"})
    apps = collections.Counter(str(a.get("App")) for a in ap)
    for a in ap:
        events.append({"t": a.get("T"), "kind": "انهيار برنامج", "info": str(a.get("App"))})
    events.sort(key=lambda e: e["t"] or "", reverse=True)
    m = {"الفترة": f"آخر {days} أيام", "شاشات زرقاء": len(bs), "إيقاف مفاجئ": len(kp), "أخطاء عتاد (WHEA)": len(wh),
         "أخطاء القرص": len(dk), "انهيار برامج": len(ap)}
    if apps:
        m["أكثر برنامج بينهار"] = "، ".join(f"{a} ({c})" for a, c in apps.most_common(3))
    if bs:
        top = [b for b in bs if "why" in b]
        why = f" السبب الأرجح: {top[0]['nm']} — {top[0]['why']}" if top else ""
        f.append(F("bad" if len(bs) >= 2 else "warn", f"حدثت {len(bs)} شاشة زرقاء خلال {days} أيام." + why,
                   "حدّث الدرايفرات (خصوصاً الشاشة والشبكة) واختبر الرامات والقرص، ولو تكررت ابعت كود الخطأ لفني"))
    if kp:
        f.append(F("bad" if len(kp) >= 3 else "warn", f"الجهاز أُغلق فجأة {len(kp)} مرة", "افحص مصدر الطاقة والحرارة، وجرّب اختبار الإجهاد"))
    if wh:
        f.append(F("bad", f"{len(wh)} خطأ عتاد من WHEA-Logger", "قد يدل على مشكلة في المعالج أو الرامات أو الحرارة؛ اختبر كل قطعة منفردة"))
    if dk:
        f.append(F("bad" if len(dk) >= 5 else "warn", f"{len(dk)} خطأ قراءة/كتابة في القرص", "انسخ بياناتك احتياطياً وافحص صحة القرص (SMART)"))
    for a, c in apps.most_common(2):
        if c >= 3:
            f.append(F("warn", f"البرنامج {a} انهار {c} مرات", "حدّثه أو أعد تثبيته"))
    return mk("crashes", "تحليل الأعطال", "💥", m, f, data={"events": events[:30]})

def c_upgrade(mods):
    by = {x["id"]: x for x in mods}
    d = lambda k: by.get(k, {}).get("data") or {}
    f = []
    ram = d("ram").get("total", 0)
    if 0 < ram < 8 * 1024 ** 3:
        f.append(F("info", f"الذاكرة {gb(ram)} قليلة", "ترقية الرامات إلى 8–16 جيجا أكبر تحسين للأداء في الغالب، وغالباً أرخص من تغيير المعالج"))
    elif 0 < ram < 16 * 1024 ** 3 and d("ram").get("pct", 0) >= 80:
        f.append(F("info", "الذاكرة ممتلئة رغم أنها 8 جيجا", "الترقية إلى 16 جيجا ستحسّن تعدد المهام"))
    if d("disks").get("hdd"):
        f.append(F("info", "نظامك أو تخزينك يعتمد على هارد HDD", "استبدل بـ SSD؛ هو أكبر تسريع ممكن للإقلاع وفتح البرامج"))
    if any(x["pct"] >= 85 for x in d("disks").get("disks", [])):
        f.append(F("info", "إحدى الأقراص شبه ممتلئة", "أضف مساحة تخزين أو انقل الملفات الكبيرة لقرص خارجي"))
    if d("cpu").get("threads", 9) <= 2:
        f.append(F("info", "المعالج ضعيف (خيطان أو أقل)", "قد تحتاج جهازاً أحدث للأعمال الثقيلة"))
    if (d("battery").get("wear") or 0) >= 30:
        f.append(F("info", f"البطارية فقدت {d('battery')['wear']}% من سعتها", "فكّر في استبدال البطارية"))
    return mk("upgrade", "نصائح الترقية", "⬆️", {"عدد النصائح": len(f)} if f else {"الحالة": "لا حاجة لترقية حالياً"}, f)

# ---------------------------------------------------------------- اختبارات الأداء والإجهاد
def _burn(stop, out, i):
    buf, n, h = os.urandom(1 << 20), 0, hashlib.sha256
    while not stop.is_set():
        h(buf).digest()
        n += 1
    out[i] = n

def burn(secs, threads):
    stop, out = threading.Event(), [0] * threads
    ts = [threading.Thread(target=_burn, args=(stop, out, i), daemon=True) for i in range(threads)]
    t0 = time.time()
    [t.start() for t in ts]
    time.sleep(secs)
    stop.set()
    [t.join() for t in ts]
    return sum(out) / (time.time() - t0)  # MB/s (SHA-256)

def bench_ram():
    if psutil.virtual_memory().available < 900 * 2 ** 20:
        return None
    n = 128 * 2 ** 20
    src, dst = bytearray(os.urandom(1 << 20) * 128), bytearray(n)
    t = time.time()
    for _ in range(6):
        dst[:] = src
    return 6 * n / 2 ** 30 / (time.time() - t)

def bench_disk():
    d = tempfile.gettempdir()
    if shutil.disk_usage(d).free < 1.5 * 2 ** 30:
        return None
    p, chunk = os.path.join(d, "pcdx_bench.tmp"), os.urandom(4 << 20)
    try:
        t = time.time()
        with open(p, "wb", buffering=0) as fh:
            for _ in range(64):
                fh.write(chunk)
            fh.flush()
            os.fsync(fh.fileno())
        w = 256 / (time.time() - t)
        t = time.time()
        with open(p, "rb", buffering=0) as fh:
            while fh.read(4 << 20):
                pass
        return w, 256 / (time.time() - t)
    finally:
        try:
            os.remove(p)
        except Exception:
            pass

def pct_vs(prev, cur):
    return f"{(cur - prev) / prev * 100:+.0f}% مقارنة بآخر اختبار" if prev else ""

def run_bench(secs=3):
    prev = (last_report("bench") or {}).get("modules", [])
    pd = {x["id"]: x.get("data", {}) for x in prev}
    n, mods = psutil.cpu_count() or 1, []
    def step(title, fn):
        STATE.update(step=title, pct=len(mods) * 100 // 3)
        mods.append(fn())
        STATE["done"].append({"title": title, "status": mods[-1]["status"]})
    def cpu():
        one, allc = burn(secs, 1), burn(secs, n)
        sc = allc / one / n * 100
        f = [F("info", pct_vs(pd.get("cpu", {}).get("multi"), allc))] if pd.get("cpu", {}).get("multi") else []
        if n > 1 and sc < 50:
            f.append(F("warn", f"كفاءة تعدد الأنوية منخفضة ({sc:.0f}%)", "أغلق البرامج الخلفية أثناء الاختبار أو افحص حرارة المعالج"))
        return mk("cpu", "أداء المعالج", "🧠", {"نواة واحدة (SHA-256)": f"{one:.0f} MB/s", f"كل الخيوط ({n})": f"{allc:.0f} MB/s",
                                                 "كفاءة التوسّع": f"{sc:.0f}%"}, f, data={"single": one, "multi": allc})
    def ram():
        s = bench_ram()
        if s is None:
            return mk("ram", "أداء الذاكرة", "🧩", {"الحالة": "الذاكرة المتاحة لا تكفي للاختبار"}, [], na=True)
        f = [F("info", pct_vs(pd.get("ram", {}).get("speed"), s))] if pd.get("ram", {}).get("speed") else []
        return mk("ram", "أداء الذاكرة", "🧩", {"سرعة النسخ": f"{s:.1f} GB/s"}, f, data={"speed": s})
    def disk():
        r = bench_disk()
        if r is None:
            return mk("disk", "أداء القرص", "💾", {"الحالة": "المساحة الحرة لا تكفي للاختبار"}, [], na=True)
        w, rd = r
        tier = "NVMe/SSD سريع" if w > 800 else "SSD" if w > 250 else "قرص متوسط" if w > 80 else "بطيء (HDD تقليدي غالباً)"
        f = [F("warn", f"سرعة الكتابة {w:.0f} MB/s منخفضة", "فكّر في الترقية إلى SSD")] if w < 80 else []
        if pd.get("disk", {}).get("w"):
            f.append(F("info", pct_vs(pd["disk"]["w"], w)))
        return mk("disk", "أداء القرص", "💾", {"كتابة متتالية": f"{w:.0f} MB/s", "قراءة متتالية (تقريبية، قد تتأثر بالكاش)": f"{rd:.0f} MB/s", "الفئة": tier},
                  f, data={"w": w, "r": rd})
    step("المعالج", cpu)
    step("الذاكرة", ram)
    step("القرص", disk)
    STATE["report_id"] = save_report("bench", mods)["id"]

def run_stress(secs=60):
    secs, n = max(20, min(int(secs), 180)), psutil.cpu_count() or 1
    stop, out, series, tmp = threading.Event(), [0] * n, [], None
    ts = [threading.Thread(target=_burn, args=(stop, out, i), daemon=True) for i in range(n)]
    psutil.cpu_percent()
    t0 = time.time()
    [t.start() for t in ts]
    STATE["step"] = "اختبار الإجهاد (حمل كامل على المعالج)"
    try:
        while time.time() - t0 < secs and not STOP.is_set():
            time.sleep(1.5)
            fr = psutil.cpu_freq()
            if len(series) % 3 == 0:
                tmp = cpu_temp()
            series.append({"t": round(time.time() - t0, 1), "cpu": psutil.cpu_percent(), "freq": int(fr.current) if fr else None,
                           "temp": round(tmp, 1) if tmp else None})
            STATE.update(series=series, pct=int((time.time() - t0) * 100 / secs))
    finally:
        stop.set()
        [t.join() for t in ts]
    temps = [p["temp"] for p in series if p["temp"]]
    freqs = [p["freq"] for p in series if p["freq"]]
    avg = sum(p["cpu"] for p in series) / max(len(series), 1)
    m = {"المدة": f"{int(series[-1]['t']) if series else 0} ثانية", "متوسط الحمل": f"{avg:.0f}%"}
    f = []
    if temps:
        m["أعلى حرارة"] = f"{max(temps):.0f}°C"
        m["حرارة البداية → النهاية"] = f"{temps[0]:.0f}° → {temps[-1]:.0f}°"
        if max(temps) >= 95:
            f.append(F("bad", f"الحرارة وصلت {max(temps):.0f}°C تحت الحمل", "نظّف الغبار وغيّر المعجون الحراري وحسّن التبريد"))
        elif max(temps) >= 85:
            f.append(F("warn", f"الحرارة مرتفعة تحت الحمل ({max(temps):.0f}°C)", "تأكد من التبريد والتهوية"))
        else:
            f.append(F("info", "الحرارة ضمن الحدود الآمنة تحت الحمل الكامل"))
    else:
        f.append(F("info", "لم تتوفر قراءات حرارة (شغّل كمسؤول)؛ الاختبار قاس الثبات فقط"))
    if len(freqs) >= 6:
        a, b = sum(freqs[:len(freqs) // 3]) / (len(freqs) // 3), sum(freqs[-(len(freqs) // 3):]) / (len(freqs) // 3)
        m["سرعة المعالج بداية → نهاية"] = f"{a:.0f} → {b:.0f} MHz"
        if b < a * 0.85:
            f.append(F("warn", "انخفضت سرعة المعالج أثناء الحمل (Throttling)", "السبب غالباً حرارة أو إمداد طاقة ضعيف"))
    if avg < 80 and series:
        f.append(F("warn", f"الحمل لم يصل للحد الأقصى (متوسط {avg:.0f}%)", "أغلق البرامج الخلفية وأعد الاختبار"))
    if STOP.is_set():
        f.append(F("info", "تم إيقاف الاختبار يدوياً قبل اكتماله"))
    STATE["report_id"] = save_report("stress", [mk("stress", "اختبار الإجهاد", "🔥", m, f, data={"series": series})])["id"]

# ---------------------------------------------------------------- تحليل المساحة / SFC / توقع
def run_du(path):
    path = os.path.abspath(os.path.expandvars(path or os.path.expanduser("~")))
    if not os.path.isdir(path):
        STATE["msg"] = "المسار غير موجود"
        return
    t0, cnt, files, tops, partial = time.time(), 0, [], collections.Counter(), False
    stack = [(path, None)]
    while stack:
        d, top = stack.pop()
        if time.time() - t0 > 90 or STOP.is_set():
            partial = True
            break
        try:
            it = list(os.scandir(d))
        except Exception:
            continue
        for e in it:
            try:
                if e.is_symlink() or (hasattr(e, "is_junction") and e.is_junction()):
                    continue
                if e.is_dir(follow_symlinks=False):
                    stack.append((e.path, top or e.name))
                else:
                    sz = e.stat(follow_symlinks=False).st_size
                    tops[top or "(ملفات مباشرة)"] += sz
                    cnt += 1
                    if len(files) < 15:
                        heapq.heappush(files, (sz, e.path))
                    elif sz > files[0][0]:
                        heapq.heapreplace(files, (sz, e.path))
            except Exception:
                pass
        STATE.update(msg=f"تم فحص {cnt} ملف…", pct=min(95, int((time.time() - t0) / 90 * 100)))
    STATE["du"] = {"path": path, "partial": partial, "count": cnt, "folders": [[k, v] for k, v in tops.most_common(15)],
                   "files": [[p, s] for s, p in sorted(files, reverse=True)]}

def run_sfc():
    if not IS_WIN:
        STATE["msg"] = "SFC متاح على ويندوز فقط"
        return
    if not is_admin():
        STATE["msg"] = "يتطلب صلاحيات المسؤول: شغّل البرنامج بـ run_as_admin.bat"
        return
    STATE.update(step="فحص ملفات النظام SFC (قد يستغرق 10–20 دقيقة)", pct=50)
    try:
        r = subprocess.run(["sfc", "/scannow"], capture_output=True, timeout=2400, creationflags=NOWIN)
        txt = (r.stdout or b"").decode("utf-16-le", "ignore").replace("\x00", "") if b"\x00" in (r.stdout or b"") else (r.stdout or b"").decode("utf-8", "ignore")
        lines = [x.strip() for x in txt.replace("\r", "\n").split("\n") if x.strip() and "%" not in x]
        STATE["msg"] = (lines[-1] if lines else f"انتهى (كود {r.returncode})") + f"  [كود الخروج {r.returncode}]"
    except Exception as e:
        STATE["msg"] = f"تعذّر التشغيل: {e}"

def slope(pts):
    n, sx, sy = len(pts), sum(p[0] for p in pts), sum(p[1] for p in pts)
    d = n * sum(p[0] ** 2 for p in pts) - sx * sx
    return (n * sum(p[0] * p[1] for p in pts) - sx * sy) / d if d else 0

def predict():
    rs = [load_report(x["id"]) for x in list_reports() if x["kind"] == "scan"]
    rs = sorted([r for r in rs if r], key=lambda r: r["date"])
    if len(rs) < 3:
        return {"ok": False, "msg": "تحتاج 3 فحوصات شاملة على الأقل، على مدى يوم أو أكثر، لحساب التوقعات"}
    ts = [datetime.datetime.strptime(r["date"], "%Y-%m-%d %H:%M") for r in rs]
    days = [(t - ts[0]).total_seconds() / 86400 for t in ts]
    if days[-1] < 1:
        return {"ok": False, "msg": "الفحوصات متقاربة جداً؛ اعمل فحصاً آخر بعد يوم أو أكثر"}
    disks, wear = {}, {}
    for r, dy in zip(rs, days):
        for m in r["modules"]:
            if m["id"] == "disks":
                for k in (m.get("data") or {}).get("disks", []):
                    disks.setdefault(k["m"], []).append((dy, k["used"], k["total"]))
                for k in (m.get("data") or {}).get("phys", []):
                    if k.get("wear") is not None:
                        wear.setdefault(k["name"], []).append((dy, k["wear"]))
    out = []
    for mnt, p in disks.items():
        if len(p) >= 3:
            s = slope([(a, b) for a, b, _ in p])
            free = p[-1][2] - p[-1][1]
            out.append({"name": f"مساحة {mnt}", "free_gb": round(free / 2 ** 30, 1), "rate": round(s / 2 ** 30, 2),
                        "days": round(free / s) if s > 2 ** 20 else None, "unit": "GB/يوم"})
    for nm, p in wear.items():
        if len(p) >= 3:
            s = slope(p)
            out.append({"name": f"استهلاك {nm}", "free_gb": None, "rate": round(s, 3), "days": round((100 - p[-1][1]) / s) if s > 0.001 else None, "unit": "%/يوم"})
    return {"ok": True, "items": out, "n": len(rs), "span": round(days[-1], 1)}

# ---------------------------------------------------------------- تسجيل مستمر
REC, REC_INT = {"on": False, "pts": [], "file": None}, [5]

def rec_loop(fn):
    n, t = 0, None
    while REC["on"]:
        try:
            fr, b = psutil.cpu_freq(), psutil.sensors_battery()
            if n % 3 == 0:
                t = cpu_temp()
            pt = [datetime.datetime.now().strftime("%H:%M:%S"), psutil.cpu_percent(), psutil.virtual_memory().percent,
                  round(t, 1) if t else "", int(fr.current) if fr else "", round(b.percent) if b else ""]
            REC["pts"] = (REC["pts"] + [pt])[-720:]
            with open(fn, "a", encoding="utf-8") as fh:
                fh.write(",".join(map(str, pt)) + "\n")
        except Exception:
            pass
        n += 1
        time.sleep(REC_INT[0])

def rec_start():
    if REC["on"]:
        return {"ok": True}
    name = datetime.datetime.now().strftime("log-%Y%m%d-%H%M%S.csv")
    fn = os.path.join(LOGS, name)
    with open(fn, "w", encoding="utf-8-sig") as fh:
        fh.write("time,cpu_percent,ram_percent,cpu_temp_c,cpu_mhz,battery_percent\n")
    REC.update(on=True, pts=[], file=name)
    threading.Thread(target=rec_loop, args=(fn,), daemon=True).start()
    return {"ok": True}

# ---------------------------------------------------------------- جدولة وإصلاحات وعمليات
TASK, DAYS = "PCDoctorX Weekly Scan", ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")

def sched_cmd():
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --scan'
    return f'"{shutil.which("pythonw") or sys.executable}" "{os.path.abspath(__file__)}" --scan'

def sched_status():
    if not IS_WIN:
        return {"supported": False}
    try:
        cfg = json.load(open(SETF, encoding="utf-8"))
    except Exception:
        cfg = {}
    r = subprocess.run(["schtasks", "/Query", "/TN", TASK], capture_output=True, creationflags=NOWIN)
    return {"supported": True, "enabled": r.returncode == 0, "day": cfg.get("day", "SUN"), "time": cfg.get("time", "12:00")}

def sched_set(en, day, tm):
    if not IS_WIN:
        return {"ok": False, "msg": "الجدولة متاحة على ويندوز فقط"}
    if en:
        if day not in DAYS or not re.match(r"^\d{2}:\d{2}$", tm or ""):
            return {"ok": False, "msg": "يوم أو وقت غير صالح"}
        args = ["schtasks", "/Create", "/TN", TASK, "/TR", sched_cmd(), "/SC", "WEEKLY", "/D", day, "/ST", tm, "/F"] + (["/RL", "HIGHEST"] if is_admin() else [])
        json.dump({"day": day, "time": tm}, open(SETF, "w", encoding="utf-8"))
    else:
        args = ["schtasks", "/Delete", "/TN", TASK, "/F"]
    r = subprocess.run(args, capture_output=True, text=True, errors="replace", creationflags=NOWIN)
    return {"ok": r.returncode == 0, "msg": "تم" if r.returncode == 0 else (r.stderr or r.stdout or "فشل").strip()[:200]}

def notify(text):
    t = text.replace("'", " ")
    ps("Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $n=New-Object System.Windows.Forms.NotifyIcon; "
       "$n.Icon=[System.Drawing.SystemIcons]::Warning; $n.Visible=$true; "
       f"$n.ShowBalloonTip(10000,'PC Doctor X','{t}',[System.Windows.Forms.ToolTipIcon]::Warning); Start-Sleep 11; $n.Dispose()", 25)

def headless():
    prev = last_report("scan")
    r = scan_core()
    if prev and (r["score"] <= prev["score"] - 10 or r["bad"] > prev["bad"]):
        notify(f"انخفضت صحة الجهاز من {prev['score']} إلى {r['score']}. افتح PC Doctor X لعرض التقرير.")

def fix(name):
    if name == "clean_temp":
        freed, n, cut, dirs = 0, 0, time.time() - 86400, {tempfile.gettempdir()}
        if IS_WIN:
            dirs.add(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"))
        for d in dirs:
            for root, _, files in os.walk(d):
                for fn in files:
                    p = os.path.join(root, fn)
                    try:
                        if os.path.getmtime(p) < cut:
                            sz = os.path.getsize(p)
                            os.remove(p)
                            freed, n = freed + sz, n + 1
                    except Exception:
                        pass
        return {"ok": True, "msg": f"تم حذف {n} ملف مؤقت (أقدم من يوم) وتحرير {freed / 2 ** 20:.0f} MB"}
    if not IS_WIN:
        return {"ok": False, "msg": "هذا الإجراء متاح على ويندوز فقط"}
    if name == "flush_dns":
        return {"ok": True, "msg": (run(["ipconfig", "/flushdns"], 15) or "تم").splitlines()[-1]}
    if name == "empty_bin":
        ps("Clear-RecycleBin -Force -ErrorAction SilentlyContinue", 60)
        return {"ok": True, "msg": "تم إفراغ سلة المحذوفات"}
    opens = {"open_update": "ms-settings:windowsupdate", "open_startup": "ms-settings:startupapps", "open_devmgr": "devmgmt.msc", "open_cleanmgr": "cleanmgr"}
    if name in opens:
        try:
            os.startfile(opens[name])
            return {"ok": True, "msg": "تم فتح الأداة"}
        except Exception as e:
            return {"ok": False, "msg": f"تعذّر الفتح: {e}"}
    return {"ok": False, "msg": "إجراء غير معروف"}

PROT = {"system", "system idle process", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "smss.exe", "registry", "explorer.exe"}

def procs(sort):
    n, rows = psutil.cpu_count() or 1, []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            rows.append({"pid": p.pid, "name": p.info["name"] or "?", "cpu": round(p.cpu_percent(None) / n, 1), "ram": round(p.memory_info().rss / 2 ** 20)})
        except Exception:
            pass
    rows.sort(key=lambda x: -x["cpu" if sort == "cpu" else "ram"])
    return rows[:25]

def kill(pid):
    try:
        p = psutil.Process(int(pid))
        if p.pid in (0, 4, os.getpid()) or (p.name() or "").lower() in PROT:
            return {"ok": False, "msg": "لا يمكن إنهاء عملية نظام أساسية"}
        nm = p.name()
        p.terminate()
        return {"ok": True, "msg": f"تم إنهاء {nm}"}
    except Exception as e:
        return {"ok": False, "msg": f"تعذّر الإنهاء: {e}"}

# ---------------------------------------------------------------- المهام والتقارير
STEPS = [("system", "معلومات النظام", c_system), ("cpu", "المعالج", c_cpu), ("ram", "الذاكرة", c_ram),
         ("disks", "الأقراص", c_disks), ("gpu", "كارت الشاشة", c_gpu), ("drivers", "الدرايفرات", c_drivers),
         ("security", "الأمان", c_security), ("startup", "برامج الإقلاع", c_startup), ("network", "الشبكة", c_network),
         ("battery", "البطارية", c_battery), ("crashes", "الأعطال", c_crashes)]
STATE = {"kind": None, "running": False, "step": "", "pct": 0, "done": [], "report_id": None, "msg": "", "series": [], "du": None}
STOP = threading.Event()

def save_report(kind, mods):
    fl = [x for m in mods for x in m["findings"]]
    bad, warn = sum(x["sev"] == "bad" for x in fl), sum(x["sev"] == "warn" for x in fl)
    now = datetime.datetime.now()
    r = {"id": now.strftime("%Y%m%d-%H%M%S"), "kind": kind, "date": now.strftime("%Y-%m-%d %H:%M"), "host": platform.node(),
         "score": max(0, 100 - 15 * bad - 5 * warn) if kind == "scan" else None, "bad": bad, "warn": warn,
         "admin": is_admin(), "version": VER, "modules": mods}
    with open(os.path.join(DATA, r["id"] + ".json"), "w", encoding="utf-8") as fh:
        json.dump(r, fh, ensure_ascii=False)
    return r

def scan_core():
    mods = []
    for i, (id_, title, fn) in enumerate(STEPS):
        STATE.update(step=title, pct=i * 100 // (len(STEPS) + 1))
        try:
            mods.append(fn())
        except Exception as e:
            mods.append(mk(id_, title, "⚠️", {}, [F("info", f"تعذّر فحص هذا الجزء: {e}")], na=True))
        STATE["done"].append({"title": title, "status": mods[-1]["status"]})
    mods.append(c_upgrade(mods))
    return save_report("scan", mods)

def run_scan():
    STATE["report_id"] = scan_core()["id"]

def start_job(kind, fn, *a):
    if STATE["running"]:
        return False
    STATE.update(kind=kind, running=True, step="", pct=0, done=[], report_id=None, msg="", series=[], du=None)
    STOP.clear()
    def w():
        try:
            fn(*a)
        except Exception as e:
            STATE["msg"] = f"خطأ: {e}"
        finally:
            STATE.update(running=False, pct=100, step="")
    threading.Thread(target=w, daemon=True).start()
    return True

def list_reports():
    out = []
    for fn in sorted(os.listdir(DATA), reverse=True):
        if fn.endswith(".json") and ID_RE.match(fn[:-5]):
            try:
                r = json.load(open(os.path.join(DATA, fn), encoding="utf-8"))
                out.append({"id": r["id"], "date": r["date"], "host": r["host"], "score": r.get("score"), "bad": r.get("bad", 0),
                            "warn": r.get("warn", 0), "kind": r.get("kind", "scan")})
            except Exception:
                pass
    return out

def load_report(i):
    if not ID_RE.match(i):
        return None
    try:
        return json.load(open(os.path.join(DATA, i + ".json"), encoding="utf-8"))
    except Exception:
        return None

def last_report(kind):
    for x in list_reports():
        if x["kind"] == kind:
            return load_report(x["id"])

# ---------------------------------------------------------------- صفحة التقرير
ST = {"ok": ("سليم", "#16a34a"), "warn": ("تحذير", "#d97706"), "bad": ("مشكلة", "#dc2626"), "na": ("غير متاح", "#64748b")}
KT = {"scan": "تقرير فحص شامل", "bench": "نتائج اختبار الأداء", "stress": "نتائج اختبار الإجهاد"}
RCSS = """body{font-family:Segoe UI,Tahoma,Arial,sans-serif;background:#f1f5f9;color:#0f172a;margin:0;line-height:1.8}
.w{max-width:860px;margin:auto;padding:24px}h1{margin:0}.sub{color:#64748b}
.score{display:flex;align-items:center;gap:20px;background:#fff;border-radius:16px;padding:20px;margin:18px 0}
.big{font-size:3rem;font-weight:800}.card{background:#fff;border-radius:14px;padding:16px 20px;margin-bottom:14px;break-inside:avoid}
h3{margin:0 0 8px}h3 em{font-style:normal;color:#fff;font-size:.75rem;padding:2px 10px;border-radius:10px;margin-inline-start:8px}
table{width:100%;border-collapse:collapse;font-size:.92rem}td{padding:5px 8px;border-bottom:1px solid #e2e8f0;vertical-align:top}td:first-child{color:#64748b;width:34%}
ul{padding-inline-start:20px;margin:8px 0 0}li.bad b{color:#dc2626}li.warn b{color:#d97706}li span{color:#475569;font-size:.9rem}
button{font:inherit;padding:8px 18px;border:0;border-radius:10px;background:#0891b2;color:#fff;cursor:pointer}
@media print{body{background:#fff}button{display:none}}"""

def svg_chart(series):
    def line(key, mx, col):
        pts = [(i, p[key]) for i, p in enumerate(series) if p.get(key) is not None]
        if len(pts) < 2:
            return ""
        return f'<polyline fill="none" stroke="{col}" stroke-width="2" points="' + " ".join(
            f"{40 + i / max(len(series) - 1, 1) * 540:.0f},{150 - min(v, mx) / mx * 130:.0f}" for i, v in pts) + '"/>'
    return ('<svg viewBox="0 0 600 165" style="width:100%;background:#f8fafc;border-radius:8px">'
            + line("cpu", 100, "#0891b2") + line("temp", 110, "#dc2626")
            + '<text x="44" y="14" font-size="11" fill="#0891b2">المعالج %</text><text x="130" y="14" font-size="11" fill="#dc2626">الحرارة °C</text></svg>')

def rhtml(r):
    e = html.escape
    mods = ""
    for m in r["modules"]:
        lab, col = ST[m["status"]]
        rows = "".join(f"<tr><td>{e(str(k))}</td><td>{e(str(v))}</td></tr>" for k, v in m["metrics"].items())
        fi = "".join(f'<li class="{x["sev"]}"><b>{e(x["text"])}</b>' + (f'<br><span>التوصية: {e(x["fix"])}</span>' if x["fix"] else "") + "</li>"
                     for x in m["findings"])
        extra = ""
        d = m.get("data") or {}
        if d.get("series"):
            extra += svg_chart(d["series"])
        if d.get("events"):
            extra += "<table>" + "".join(f"<tr><td>{e(str(x['t']))}</td><td>{e(x['kind'])}</td><td>{e(x['info'])}</td></tr>" for x in d["events"][:25]) + "</table>"
        mods += f'<section class="card"><h3>{m["icon"]} {e(m["title"])} <em style="background:{col}">{lab}</em></h3><table>{rows}</table>{extra}<ul>{fi}</ul></section>'
    recs = sorted([(x, m["title"]) for m in r["modules"] for x in m["findings"] if x["fix"] and x["sev"] != "info"], key=lambda t: -SEV[t[0]["sev"]])
    rl = "".join(f'<li class="{x["sev"]}"><b>{e(t)}:</b> {e(x["fix"])}</li>' for x, t in recs) or "<li>لا توجد إجراءات مطلوبة، جهازك بحالة جيدة.</li>"
    kind = r.get("kind", "scan")
    head, summ = "", ""
    if kind == "scan":
        s = r["score"]
        col = "#16a34a" if s >= 85 else "#d97706" if s >= 65 else "#dc2626"
        lab = "ممتازة" if s >= 85 else "تحتاج اهتمام" if s >= 65 else "حرجة"
        head = f'<div class="score"><div class="big" style="color:{col}">{s}</div><div><b>صحة الجهاز: {lab}</b><br>{r["bad"]} مشاكل · {r["warn"]} تحذيرات</div></div>'
        summ = f'<section class="card"><h3>✅ التوصيات بالأولوية</h3><ul>{rl}</ul></section>'
    adm = "" if r.get("admin") else '<p class="sub">ملاحظة: تم الفحص بدون صلاحيات المسؤول، وبعض القراءات (الحرارة، حالة الأقراص) تكون أدق عند التشغيل كمسؤول.</p>'
    return f'''<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>{KT.get(kind, "تقرير")} — {e(r["date"])}</title><style>{RCSS}</style></head><body><div class="w">
<h1>🩺 {KT.get(kind, "تقرير")}</h1><p class="sub">{e(r["host"])} — {e(r["date"])} — PC Doctor X {e(r.get("version", ""))}</p>{head}{adm}{summ}{mods}
<p><button onclick="print()">🖨️ طباعة / حفظ PDF</button></p></div></body></html>'''

# ---------------------------------------------------------------- الخادم
NET = [time.time(), 0, 0]

def live():
    n = psutil.net_io_counters()
    t = time.time()
    dt = max(t - NET[0], 0.001)
    down, up = (n.bytes_recv - NET[2]) / dt if NET[2] else 0, (n.bytes_sent - NET[1]) / dt if NET[1] else 0
    NET[:] = [t, n.bytes_sent, n.bytes_recv]
    root = os.path.abspath(os.sep) if not IS_WIN else os.environ.get("SystemDrive", "C:") + "\\"
    try:
        d = psutil.disk_usage(root).percent
    except Exception:
        d = 0
    return {"cpu": psutil.cpu_percent(), "ram": psutil.virtual_memory().percent, "disk": d, "down": down, "up": up}

def find_browser():
    cands = (r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe", r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
             r"%ProgramFiles%\Google\Chrome\Application\chrome.exe", r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
             r"%LocalAppData%\Google\Chrome\Application\chrome.exe") if IS_WIN else ()
    for p in cands:
        p = os.path.expandvars(p)
        if os.path.exists(p):
            return p
    return None if IS_WIN else (shutil.which("chromium") or shutil.which("google-chrome") or shutil.which("chromium-browser"))

def make_pdf(rid):
    exe = find_browser()
    if not exe:
        return None
    out, prof = os.path.join(tempfile.gettempdir(), f"pcdx-{rid}.pdf"), tempfile.mkdtemp(prefix="pcdx-")
    run([exe, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--user-data-dir={prof}", f"--print-to-pdf={out}",
         f"http://127.0.0.1:{PORT[0]}/report/{rid}?t={TOKEN}"], 60)
    shutil.rmtree(prof, ignore_errors=True)
    try:
        return open(out, "rb").read()
    except Exception:
        return None

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def out(self, obj, code=200, ctype=None, headers=None):
        if isinstance(obj, (dict, list)):
            data, ctype = json.dumps(obj, ensure_ascii=False).encode(), ctype or "application/json; charset=utf-8"
        elif isinstance(obj, bytes):
            data = obj
        else:
            data, ctype = obj.encode("utf-8"), ctype or "text/html; charset=utf-8"
        self.send_response(code)
        self.send_header("Content-Type", ctype or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        try:
            return json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        except Exception:
            return {}

    def allowed(self, q):
        return self.headers.get("Host") in ALLOWED and (self.headers.get("X-Token") == TOKEN or q.get("t", [""])[0] == TOKEN)

    def do_GET(self):
        u = urlparse(self.path)
        q, p = parse_qs(u.query), u.path
        if self.headers.get("Host") not in ALLOWED:
            return self.out({"error": "forbidden"}, 403)
        if p == "/":
            return self.out(UI.replace("__TOKEN__", TOKEN))
        if not self.allowed(q):
            return self.out({"error": "forbidden"}, 403)
        if p == "/api/info":
            return self.out({"admin": is_admin(), "version": VER, "host": platform.node(), "win": IS_WIN})
        if p == "/api/live":
            return self.out(live())
        if p == "/api/ping":
            LAST_PING[0] = time.time()
            return self.out({"ok": 1})
        if p == "/api/job/status":
            return self.out(STATE)
        if p == "/api/reports":
            return self.out(list_reports())
        if p == "/api/crashes":
            return self.out(c_crashes(int(q.get("days", ["7"])[0])))
        if p == "/api/procs":
            return self.out(procs(q.get("sort", ["cpu"])[0]))
        if p == "/api/predict":
            return self.out(predict())
        if p == "/api/sched":
            return self.out(sched_status())
        if p == "/api/rec/data":
            return self.out({"on": REC["on"], "file": REC["file"], "pts": REC["pts"][-360:]})
        if p == "/api/rec/list":
            return self.out(sorted([f for f in os.listdir(LOGS) if re.match(r"^log-\d{8}-\d{6}\.csv$", f)], reverse=True)[:15])
        if p == "/api/rec/csv":
            f = q.get("f", [""])[0]
            if not re.match(r"^log-\d{8}-\d{6}\.csv$", f) or not os.path.exists(os.path.join(LOGS, f)):
                return self.out({"error": "not found"}, 404)
            return self.out(open(os.path.join(LOGS, f), "rb").read(), ctype="text/csv; charset=utf-8",
                            headers={"Content-Disposition": f'attachment; filename="{f}"'})
        m = re.match(r"^/api/reports/(\d{8}-\d{6})(/pdf)?$", p)
        if m:
            r = load_report(m.group(1))
            if not r:
                return self.out({"error": "not found"}, 404)
            if m.group(2):
                pdf = make_pdf(r["id"])
                if not pdf:
                    return self.out({"error": "pdf unavailable"}, 500)
                return self.out(pdf, ctype="application/pdf", headers={"Content-Disposition": f'attachment; filename="pcdoctorx-{r["id"]}.pdf"'})
            h = {"Content-Disposition": f'attachment; filename="pcdoctorx-{r["id"]}.json"'} if q.get("dl") else None
            return self.out(r, headers=h)
        m = re.match(r"^/report/(\d{8}-\d{6})$", p)
        if m:
            r = load_report(m.group(1))
            return self.out(rhtml(r)) if r else self.out("غير موجود", 404)
        self.out({"error": "not found"}, 404)

    def do_POST(self):
        q, p = parse_qs(urlparse(self.path).query), urlparse(self.path).path
        if not self.allowed(q):
            return self.out({"error": "forbidden"}, 403)
        b = self.body()
        if p == "/api/job/start":
            k = b.get("kind")
            jobs = {"scan": (run_scan,), "bench": (run_bench,), "stress": (run_stress, b.get("secs", 60)), "sfc": (run_sfc,), "du": (run_du, b.get("path", ""))}
            if k not in jobs:
                return self.out({"ok": False, "msg": "مهمة غير معروفة"})
            return self.out({"ok": start_job(k, *jobs[k]), "msg": "" if not STATE["running"] or STATE["kind"] == k else "هناك مهمة أخرى قيد التنفيذ"})
        if p == "/api/job/stop":
            STOP.set()
            return self.out({"ok": True})
        if p == "/api/fix":
            return self.out(fix(b.get("name", "")))
        if p == "/api/proc/kill":
            return self.out(kill(b.get("pid")))
        if p == "/api/rec/start":
            return self.out(rec_start())
        if p == "/api/rec/stop":
            REC["on"] = False
            return self.out({"ok": True})
        if p == "/api/sched/set":
            return self.out(sched_set(bool(b.get("enabled")), b.get("day", "SUN"), b.get("time", "12:00")))
        m = re.match(r"^/api/reports/(\d{8}-\d{6})/delete$", p)
        if m:
            try:
                os.remove(os.path.join(DATA, m.group(1) + ".json"))
            except Exception:
                pass
            return self.out({"ok": 1})
        if p == "/api/quit":
            self.out({"ok": 1})
            threading.Timer(0.3, lambda: os._exit(0)).start()
            return
        self.out({"error": "not found"}, 404)

def open_ui(url):
    exe = find_browser() if IS_WIN else None
    if exe:
        subprocess.Popen([exe, f"--app={url}", "--window-size=1180,800"])
    else:
        webbrowser.open(url)

def main():
    if "--scan" in sys.argv:
        headless()
        return
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    PORT[0] = srv.server_address[1]
    ALLOWED.update({f"127.0.0.1:{PORT[0]}", f"localhost:{PORT[0]}"})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    live()
    open_ui(f"http://127.0.0.1:{PORT[0]}/")
    while True:  # يغلق البرنامج تلقائياً عند إغلاق النافذة
        time.sleep(5)
        if (LAST_PING[0] and time.time() - LAST_PING[0] > 150) or (not LAST_PING[0] and time.time() - START > 120):
            break
    os._exit(0)

# ---------------------------------------------------------------- الواجهة
UI = r'''<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PC Doctor X</title><style>
:root{--bg:#0a111d;--card:#111b2c;--text:#e8eff9;--muted:#8fa2bd;--line:#1f2d45;--acc:#22d3ee;--acc2:#60a5fa;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171}
[data-t=light]{--bg:#f1f5f9;--card:#fff;--text:#0f172a;--muted:#64748b;--line:#dbe4ee;--acc:#0891b2;--acc2:#2563eb;--ok:#16a34a;--warn:#d97706;--bad:#dc2626}
*{box-sizing:border-box;margin:0}body{background:var(--bg);color:var(--text);font-family:Segoe UI,Tahoma,Arial,sans-serif;display:flex;min-height:100vh;line-height:1.7}
aside{width:200px;flex:none;background:var(--card);border-inline-end:1px solid var(--line);padding:16px 10px;display:flex;flex-direction:column;gap:4px}
.logo{font-weight:800;font-size:1.1rem;margin-bottom:12px;padding:0 8px}.logo b{color:var(--acc)}
aside button{font:inherit;text-align:start;background:none;border:0;color:var(--muted);padding:9px 12px;border-radius:10px;cursor:pointer}
aside button.on,aside button:hover{background:var(--line);color:var(--text)}.sp{margin-top:auto}
main{flex:1;min-width:0;padding:22px;overflow:auto}h2{margin-bottom:12px}h3{margin:14px 0 8px;font-size:1rem}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}
.c{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:12px}.c small,.m{color:var(--muted)}.v{font-size:1.8rem;font-weight:800}
.bar{height:8px;background:var(--line);border-radius:8px;margin:8px 0;overflow:hidden}.bar i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--acc),var(--acc2));transition:width .4s}
canvas{width:100%;height:70px;margin-top:6px}.btn{font:inherit;background:linear-gradient(135deg,var(--acc),var(--acc2));color:#04121c;font-weight:700;border:0;border-radius:11px;padding:10px 22px;cursor:pointer;margin:3px 0}
.btn:disabled{opacity:.45}.btn.s{padding:4px 12px;font-size:.85rem;background:var(--line);color:var(--text);font-weight:400;text-decoration:none;display:inline-block}
.step{display:flex;gap:10px;padding:4px 0;border-bottom:1px dashed var(--line)}.d{width:10px;height:10px;border-radius:50%;margin-top:9px;background:var(--line);flex:none}
.d.ok{background:var(--ok)}.d.warn{background:var(--warn)}.d.bad{background:var(--bad)}.d.na{background:var(--muted)}.d.run{background:var(--acc)}
.tip{background:rgba(251,191,36,.12);border:1px solid var(--warn);color:var(--warn);border-radius:12px;padding:10px 14px;margin-bottom:14px;font-size:.9rem}
table{width:100%;border-collapse:collapse;font-size:.92rem}th,td{padding:7px 8px;text-align:start;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600;font-size:.82rem}
.sc{font-size:2.8rem;font-weight:800}.f{padding:5px 0;font-size:.92rem}.f.bad b{color:var(--bad)}.f.warn b{color:var(--warn)}.f span{color:var(--muted)}
input,select{font:inherit;background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:6px 10px}[hidden]{display:none!important}
</style></head><body>
<aside><div class="logo">🩺 PC Doctor <b>X</b></div>
<button data-p="dash" class="on">📊 المراقبة والتسجيل</button><button data-p="scan">🔍 الفحص الشامل</button><button data-p="test">⚡ الأداء والإجهاد</button>
<button data-p="crash">💥 تحليل الأعطال</button><button data-p="procs">⚙️ العمليات</button><button data-p="tools">🛠️ الصيانة والجدولة</button><button data-p="hist">🗂️ التقارير والتوقعات</button>
<button class="sp" id="th">🌓 الوضع الفاتح/الغامق</button><button id="quit">⏻ إغلاق البرنامج</button></aside>
<main><div id="admtip" class="tip" hidden>💡 شغّل البرنامج كمسؤول (Run as administrator) للحصول على قراءات أدق لحرارة المعالج وحالة الأقراص.</div>

<section class="pg" id="dash"><h2>المراقبة الحية</h2><div class="grid">
<div class="c"><small>المعالج</small><div class="v" id="vcpu">--</div><canvas id="ccpu" width="260" height="70"></canvas></div>
<div class="c"><small>الذاكرة</small><div class="v" id="vram">--</div><canvas id="cram" width="260" height="70"></canvas></div>
<div class="c"><small>القرص الرئيسي</small><div class="v" id="vdisk">--</div><div class="bar"><i id="bdisk"></i></div></div>
<div class="c"><small>الشبكة</small><div>⬇ <b id="vdown">--</b></div><div>⬆ <b id="vup">--</b></div></div></div>
<h3>📈 التسجيل المستمر (CPU / RAM / الحرارة)</h3><div class="c"><button class="btn" id="rbtn">⏺ ابدأ التسجيل</button> <span class="m" id="rst">متوقف — يسجّل كل 5 ثوانٍ ويحفظ ملف CSV</span>
<canvas id="crec" width="900" height="120"></canvas><small>الأزرق: المعالج · الفاتح: الذاكرة · الأحمر: الحرارة</small><div id="rlogs" style="margin-top:8px"></div></div></section>

<section class="pg" id="scan" hidden><h2>فحص شامل للجهاز</h2><p class="m" style="margin-bottom:12px">يفحص 11 جزءاً (بما فيها تحليل الأعطال) ويحفظ تقريراً ونصائح ترقية. يستغرق حوالي دقيقة إلى دقيقتين.</p>
<button class="btn jb" id="sbtn">▶ ابدأ الفحص</button><div class="bar"><i id="spb"></i></div><div id="ssteps"></div><div id="sres"></div></section>

<section class="pg" id="test" hidden><h2>اختبارات الأداء والإجهاد</h2>
<div class="grid"><div class="c"><h3 style="margin-top:0">🏁 اختبار الأداء (Benchmark)</h3><p class="m">يقيس المعالج (نواة/كل الأنوية) والذاكرة والقرص ويقارن بآخر اختبار. حوالي 30 ثانية.</p><button class="btn jb" id="bbtn">▶ ابدأ الاختبار</button></div>
<div class="c"><h3 style="margin-top:0">🔥 اختبار الإجهاد</h3><p class="m">يحمّل المعالج بالكامل ويراقب الحرارة والثبات. ⚠️ قد يسخّن الجهاز؛ تأكد من التهوية.</p>
<select id="ssec"><option value="30">30 ثانية</option><option value="60" selected>60 ثانية</option><option value="120">120 ثانية</option></select>
<button class="btn jb" id="xbtn">▶ ابدأ</button> <button class="btn s" id="xstop">⏹ إيقاف</button></div></div>
<div class="bar"><i id="tpb"></i></div><canvas id="tcv" width="900" height="110" hidden></canvas><div id="tsteps"></div><div id="tres"></div></section>

<section class="pg" id="crash" hidden><h2>تحليل الأعطال والشاشات الزرقاء</h2><p class="m" style="margin-bottom:12px">يقرأ سجلات ويندوز ويربط أكواد الأعطال بأسبابها المحتملة.</p>
<select id="cdays"><option value="7">آخر 7 أيام</option><option value="30">آخر 30 يوماً</option></select> <button class="btn" id="cbtn">🔎 حلّل الأعطال</button><div id="cres"></div></section>

<section class="pg" id="procs" hidden><h2>العمليات الجارية</h2><button class="btn s" id="psort">ترتيب: المعالج</button><div class="c" id="plist" style="margin-top:10px"></div></section>

<section class="pg" id="tools" hidden><h2>الصيانة والجدولة</h2><h3>🛠️ إصلاحات بضغطة</h3><div class="c" id="fixes"></div><div id="fixres"></div>
<h3>📦 أكبر الملفات والمجلدات</h3><div class="c"><input id="dupath" size="34" placeholder="مثال: C:\Users\اسمك" dir="ltr"> <button class="btn jb" id="dubtn">تحليل المساحة</button>
<div class="bar"><i id="mpb"></i></div><div id="msteps"></div><div id="mres"></div></div>
<h3>⏰ فحص أسبوعي تلقائي</h3><div class="c" id="sched"></div></section>

<section class="pg" id="hist" hidden><h2>التقارير والتوقعات</h2>
<div class="c"><small>تطور صحة الجهاز</small><canvas id="ctrend" width="800" height="80"></canvas></div>
<div class="c"><b>🔮 توقعات من تاريخ الفحوصات</b><div id="pred" class="m"></div></div>
<div class="c" id="hl"></div><div id="cmp"></div></section>
</main><script>
const T="__TOKEN__",$=s=>document.querySelector(s),esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api=(p,o={})=>fetch(p+(p.includes('?')?'&':'?')+'t='+T,Object.assign({headers:{'X-Token':T,'Content-Type':'application/json'}},o)).then(r=>r.json());
const post=(p,b={})=>api(p,{method:'POST',body:JSON.stringify(b)});
const col=s=>s>=85?'var(--ok)':s>=65?'var(--warn)':'var(--bad)',ST={ok:'سليم',warn:'تحذير',bad:'مشكلة',na:'غير متاح'},KT={scan:'فحص',bench:'أداء',stress:'إجهاد'};
let page='dash';
function show(id){page=id;document.querySelectorAll('.pg').forEach(e=>e.hidden=e.id!==id);document.querySelectorAll('aside button[data-p]').forEach(b=>b.classList.toggle('on',b.dataset.p===id));
 if(id==='hist')loadHist();if(id==='procs')loadProcs();if(id==='tools'){loadSched();drawFixes()}if(id==='dash')loadLogs()}
document.querySelectorAll('aside button[data-p]').forEach(b=>b.onclick=()=>show(b.dataset.p));
$('#th').onclick=()=>{const d=document.documentElement,l=d.dataset.t==='light';l?delete d.dataset.t:d.dataset.t='light';try{localStorage.t=l?'':'light'}catch(e){}};
try{if(localStorage.t==='light')document.documentElement.dataset.t='light'}catch(e){}
function multi(cv,arr){const c=cv.getContext('2d'),w=cv.width,h=cv.height;c.clearRect(0,0,w,h);arr.forEach(s=>{if(s.a.length<2)return;c.strokeStyle=s.c;c.lineWidth=2;c.beginPath();let st=false;s.a.forEach((v,i)=>{if(v==null||v==='')return;const x=i/(Math.max(s.a.length-1,29))*w,y=h-3-Math.min(v,s.mx)/s.mx*(h-6);st?c.lineTo(x,y):c.moveTo(x,y);st=true});c.stroke()})}
const sp=n=>n>1048576?(n/1048576).toFixed(1)+' MB/s':(n/1024).toFixed(0)+' KB/s',Hs={cpu:[],ram:[]};
async function tick(){try{const d=await api('/api/live');for(const k of['cpu','ram']){Hs[k].push(d[k]);if(Hs[k].length>60)Hs[k].shift();$('#v'+k).textContent=d[k].toFixed(0)+'%';multi($('#c'+k),[{a:Hs[k],c:k=='cpu'?'#22d3ee':'#60a5fa',mx:100}])}
 $('#vdisk').textContent=d.disk.toFixed(0)+'%';$('#bdisk').style.width=d.disk+'%';$('#vdown').textContent=sp(d.down);$('#vup').textContent=sp(d.up)}catch(e){}}
setInterval(tick,2000);tick();setInterval(()=>api('/api/ping'),4000);api('/api/ping');
api('/api/info').then(i=>{if(i.win&&!i.admin)$('#admtip').hidden=false});
$('#quit').onclick=()=>{post('/api/quit').finally(()=>{document.body.innerHTML='<p style="padding:40px">تم إغلاق البرنامج، يمكنك إغلاق هذه النافذة.</p>';window.close()})};
/* التسجيل */
async function recTick(){if(page!=='dash')return;const d=await api('/api/rec/data');$('#rbtn').textContent=d.on?'⏹ إيقاف التسجيل':'⏺ ابدأ التسجيل';$('#rst').textContent=d.on?`يسجّل الآن (${d.pts.length} قراءة) → ${d.file}`:'متوقف — يسجّل كل 5 ثوانٍ ويحفظ ملف CSV';
 multi($('#crec'),[{a:d.pts.map(p=>p[1]),c:'#22d3ee',mx:100},{a:d.pts.map(p=>p[2]),c:'#93c5fd',mx:100},{a:d.pts.map(p=>p[3]),c:'#f87171',mx:110}])}
setInterval(recTick,3000);
$('#rbtn').onclick=async()=>{const d=await api('/api/rec/data');await post(d.on?'/api/rec/stop':'/api/rec/start');setTimeout(()=>{recTick();loadLogs()},400)};
async function loadLogs(){const l=await api('/api/rec/list');$('#rlogs').innerHTML=l.length?'ملفات التسجيل: '+l.map(f=>`<a class="btn s" href="/api/rec/csv?f=${f}&t=${T}">${f.slice(4,12)} ${f.slice(13,19)} ⬇CSV</a>`).join(' '):''}
/* المهام */
const busy=x=>document.querySelectorAll('.jb').forEach(b=>b.disabled=x);
async function job(kind,params,p){busy(true);const r=await post('/api/job/start',Object.assign({kind},params||{}));if(!r.ok){busy(false);$('#'+p+'steps').innerHTML=`<div class="f">${esc(r.msg||'تعذّر البدء')}</div>`;return}
 $('#'+p+'res').innerHTML='';if(kind==='stress')$('#tcv').hidden=false;poll(p)}
async function poll(p){const s=await api('/api/job/status');$('#'+p+'pb').style.width=s.pct+'%';
 let h=s.done.map(d=>`<div class="step"><span class="d ${d.status}"></span><span>${esc(d.title)} — ${ST[d.status]}</span></div>`).join('');
 if(s.running&&s.step)h+=`<div class="step"><span class="d run"></span><span>جاري: ${esc(s.step)}…</span></div>`;if(s.msg)h+=`<div class="f">${esc(s.msg)}</div>`;$('#'+p+'steps').innerHTML=h;
 if(s.kind==='stress'&&s.series.length)multi($('#tcv'),[{a:s.series.map(x=>x.cpu),c:'#22d3ee',mx:100},{a:s.series.map(x=>x.temp),c:'#f87171',mx:110}]);
 if(s.running){setTimeout(()=>poll(p),800);return}busy(false);if(s.report_id)showRes(s.report_id,p);if(s.du)showDu(s.du)}
$('#sbtn').onclick=()=>job('scan',{}, 's');$('#bbtn').onclick=()=>job('bench',{}, 't');
$('#xbtn').onclick=()=>{if(confirm('سيعمل المعالج بأقصى حمل. تأكد أن التهوية جيدة. متابعة؟'))job('stress',{secs:+$('#ssec').value},'t')};$('#xstop').onclick=()=>post('/api/job/stop');
async function showRes(id,p){const r=await api('/api/reports/'+id),el=$('#'+p+'res');
 const fl=r.modules.flatMap(m=>m.findings.filter(f=>f.sev!='info').map(f=>({...f,m:m.title}))).sort((a,b)=>(b.sev=='bad')-(a.sev=='bad'));
 let h=`<div class="c" style="margin-top:14px"><div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap">`+(r.kind==='scan'?`<div class="sc" style="color:${col(r.score)}">${r.score}</div><div><b>صحة الجهاز</b><br><small>${r.bad} مشاكل · ${r.warn} تحذيرات</small></div>`:`<b>${r.kind==='bench'?'نتائج اختبار الأداء':'نتائج اختبار الإجهاد'}</b>`)+
 `<button class="btn" style="margin-inline-start:auto" onclick="openR('${r.id}')">📄 فتح التقرير الكامل</button></div>`;
 if(r.kind!=='scan')h+=r.modules.map(m=>`<h3>${esc(m.icon)} ${esc(m.title)}</h3><table>`+Object.entries(m.metrics).map(([k,v])=>`<tr><td class="m">${esc(k)}</td><td>${esc(v)}</td></tr>`).join('')+'</table>'+m.findings.map(f=>`<div class="f ${f.sev}"><b>${esc(f.text)}</b> <span>${esc(f.fix||'')}</span></div>`).join('')).join('');
 else h+=(fl.length?fl.slice(0,6).map(f=>`<div class="f ${f.sev}"><b>${esc(f.m)}:</b> ${esc(f.text)}<br><span>${esc(f.fix||'')}</span></div>`).join(''):'<div class="f">لم يتم العثور على مشاكل. جهازك بحالة جيدة ✅</div>');el.innerHTML=h+'</div>'}
const openR=id=>window.open('/report/'+id+'?t='+T,'_blank'),fsz=b=>b>2**30?(b/2**30).toFixed(1)+' GB':(b/2**20).toFixed(0)+' MB';
/* الأعطال */
$('#cbtn').onclick=async()=>{$('#cres').innerHTML='<p class="m">جاري قراءة سجلات ويندوز… (قد تستغرق نصف دقيقة)</p>';const m=await api('/api/crashes?days='+$('#cdays').value);
 $('#cres').innerHTML=`<div class="c"><b>${esc(m.icon)} ${esc(m.title)} — ${ST[m.status]}</b><table>`+Object.entries(m.metrics).map(([k,v])=>`<tr><td class="m">${esc(k)}</td><td>${esc(v)}</td></tr>`).join('')+'</table>'+
 (m.findings.length?m.findings.map(f=>`<div class="f ${f.sev}"><b>${esc(f.text)}</b><br><span>${esc(f.fix||'')}</span></div>`).join(''):(m.status==='na'?'':'<div class="f">لم تُسجَّل أعطال في هذه الفترة ✅</div>'))+
 ((m.data.events||[]).length?'<h3>السجل</h3><table>'+m.data.events.map(e=>`<tr><td>${esc(e.t)}</td><td>${esc(e.kind)}</td><td>${esc(e.info)}</td></tr>`).join('')+'</table>':'')+'</div>'};
/* العمليات */
let psort='cpu';$('#psort').onclick=()=>{psort=psort==='cpu'?'ram':'cpu';$('#psort').textContent='ترتيب: '+(psort==='cpu'?'المعالج':'الذاكرة');loadProcs()};
async function loadProcs(){if(page!=='procs')return;const l=await api('/api/procs?sort='+psort);$('#plist').innerHTML='<table><tr><th>العملية</th><th>PID</th><th>المعالج %</th><th>الذاكرة MB</th><th></th></tr>'+l.map(p=>`<tr><td>${esc(p.name)}</td><td>${p.pid}</td><td>${p.cpu}</td><td>${p.ram}</td><td><button class="btn s" onclick="kp(${p.pid},'${esc(p.name)}')">إنهاء</button></td></tr>`).join('')+'</table>'}
setInterval(loadProcs,3000);
async function kp(pid,n){if(!confirm('إنهاء العملية '+n+'؟ قد تفقد أي عمل غير محفوظ فيها.'))return;const r=await post('/api/proc/kill',{pid});alert(r.msg);loadProcs()}
/* الصيانة */
const FX=[['clean_temp','🧹 تنظيف الملفات المؤقتة',1],['empty_bin','🗑️ إفراغ سلة المحذوفات',1],['flush_dns','🌐 تصفير DNS',0],['sfc','🧱 فحص ملفات النظام (SFC)',1],['open_startup','🚀 إدارة برامج الإقلاع',0],['open_update','⬆️ Windows Update',0],['open_devmgr','🔧 إدارة الأجهزة',0],['open_cleanmgr','💽 تنظيف القرص',0]];
function drawFixes(){$('#fixes').innerHTML=FX.map(f=>`<button class="btn s ${f[0]==='sfc'?'jb':''}" onclick="doFix('${f[0]}',${f[2]})">${f[1]}</button>`).join(' ')}
async function doFix(n,c){if(c&&!confirm('تنفيذ هذا الإجراء؟'))return;if(n==='sfc'){job('sfc',{},'m');return}const r=await post('/api/fix',{name:n});$('#fixres').innerHTML=`<div class="f ${r.ok?'':'bad'}">${esc(r.msg)}</div>`}
$('#dubtn').onclick=()=>job('du',{path:$('#dupath').value},'m');
function showDu(d){$('#mres').innerHTML=`<h3>${esc(d.path)} — ${d.count} ملف${d.partial?' (نتيجة جزئية)':''}</h3><table><tr><th>أكبر المجلدات</th><th>الحجم</th></tr>`+d.folders.map(x=>`<tr><td dir="ltr">${esc(x[0])}</td><td>${fsz(x[1])}</td></tr>`).join('')+'</table><table style="margin-top:10px"><tr><th>أكبر الملفات</th><th>الحجم</th></tr>'+d.files.map(x=>`<tr><td dir="ltr">${esc(x[0])}</td><td>${fsz(x[1])}</td></tr>`).join('')+'</table>'}
async function loadSched(){const s=await api('/api/sched');if(!s.supported){$('#sched').innerHTML='<span class="m">الجدولة متاحة على ويندوز فقط.</span>';return}
 $('#sched').innerHTML=`<p>الحالة: <b>${s.enabled?'مفعّل ✅':'متوقف'}</b></p><select id="sday">${['SUN','MON','TUE','WED','THU','FRI','SAT'].map((d,i)=>`<option value="${d}" ${d===s.day?'selected':''}>${['الأحد','الاثنين','الثلاثاء','الأربعاء','الخميس','الجمعة','السبت'][i]}</option>`).join('')}</select> <input id="stime" type="time" value="${s.time}"> <button class="btn s" onclick="setSched(true)">تفعيل / تحديث</button> <button class="btn s" onclick="setSched(false)">إيقاف</button><p class="m">يعمل فحصاً صامتاً ويرسل إشعاراً لو انخفضت صحة الجهاز.</p><div id="sres2"></div>`}
async function setSched(en){const r=await post('/api/sched/set',{enabled:en,day:$('#sday').value,time:$('#stime').value});$('#sres2').innerHTML=`<div class="f ${r.ok?'':'bad'}">${esc(r.msg)}</div>`;loadSched()}
/* التقارير */
let sel=[];
async function loadHist(){const l=await api('/api/reports');sel=[];multi($('#ctrend'),[{a:l.filter(x=>x.kind==='scan').map(x=>x.score).reverse(),c:'#4ade80',mx:100}]);
 $('#hl').innerHTML=l.length?'<table><tr><th></th><th>النوع</th><th>التاريخ</th><th>الصحة</th><th>مشاكل / تحذيرات</th><th></th></tr>'+l.map(x=>`<tr><td><input type="checkbox" onchange="pick('${x.id}',this)"></td><td>${KT[x.kind]||x.kind}</td><td>${esc(x.date)}</td><td style="color:${x.score==null?'inherit':col(x.score)};font-weight:700">${x.score==null?'—':x.score}</td><td>${x.bad} / ${x.warn}</td><td><button class="btn s" onclick="openR('${x.id}')">فتح</button> <button class="btn s" onclick="pdf('${x.id}')">PDF</button> <a class="btn s" href="/api/reports/${x.id}?dl=1&t=${T}">JSON</a> <button class="btn s" onclick="del('${x.id}')">حذف</button></td></tr>`).join('')+'</table><p style="margin-top:8px"><button class="btn s" id="cmpb" onclick="doCmp()">⚖️ قارن التقريرين المحدّدين</button></p>':'<p class="m">لا توجد تقارير بعد. ابدأ بفحص شامل.</p>';
 const p=await api('/api/predict');$('#pred').innerHTML=!p.ok?esc(p.msg):(p.items.length?p.items.map(i=>`<div class="f">• ${esc(i.name)}: ${i.days==null?'مستقر، لا خطر قريب':'متوقع أن يمتلئ/ينتهي بعد <b>'+i.days+' يوم</b>'} <span>(معدل ${i.rate} ${i.unit}${i.free_gb!=null?'، متبقي '+i.free_gb+' GB':''})</span></div>`).join(''):'لا بيانات كافية')}
function pick(id,el){el.checked?sel.push(id):sel=sel.filter(x=>x!==id);if(sel.length>2){alert('اختر تقريرين فقط');el.checked=false;sel=sel.filter(x=>x!==id)}}
async function pdf(id){const r=await fetch(`/api/reports/${id}/pdf?t=${T}`);if((r.headers.get('content-type')||'').includes('pdf')){const b=await r.blob(),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='PCDoctorX-'+id+'.pdf';a.click()}else alert('تعذّر إنشاء PDF مباشرة (يلزم Edge أو Chrome). افتح التقرير واستخدم زر الطباعة ← حفظ PDF.')}
async function del(id){if(confirm('حذف هذا التقرير؟')){await post('/api/reports/'+id+'/delete');loadHist()}}
function cmpHtml(a,b){const fa=new Map(),fb=new Map(),k=(m,f)=>m.title+'|'+f.text;
 a.modules.forEach(m=>m.findings.filter(f=>f.sev!='info').forEach(f=>fa.set(k(m,f),[m.title,f])));b.modules.forEach(m=>m.findings.filter(f=>f.sev!='info').forEach(f=>fb.set(k(m,f),[m.title,f])));
 const fixed=[...fa].filter(([x])=>!fb.has(x)).map(x=>x[1]),added=[...fb].filter(([x])=>!fa.has(x)).map(x=>x[1]);
 const rows=b.modules.map(m=>{const o=a.modules.find(x=>x.id===m.id);return `<tr><td>${esc(m.title)}</td><td>${o?ST[o.status]:'—'}</td><td>${ST[m.status]}</td></tr>`}).join('');
 const d=(b.score==null||a.score==null)?null:b.score-a.score;
 return `<div class="c"><h3 style="margin-top:0">⚖️ المقارنة: ${esc(a.date)} ← ${esc(b.date)}</h3>`+(d==null?'':`<p>التغير في الصحة: <b style="color:${d>=0?'var(--ok)':'var(--bad)'}">${d>0?'+':''}${d}</b> (${a.score} ← ${b.score})</p>`)+
 `<table><tr><th>الجزء</th><th>قبل</th><th>بعد</th></tr>${rows}</table><h3>✅ مشاكل اتحلّت (${fixed.length})</h3>`+fixed.map(x=>`<div class="f">${esc(x[0])}: ${esc(x[1].text)}</div>`).join('')+`<h3>⚠️ مشاكل جديدة (${added.length})</h3>`+added.map(x=>`<div class="f bad">${esc(x[0])}: ${esc(x[1].text)}</div>`).join('')+'</div>'}
async function doCmp(){if(sel.length!==2){alert('حدّد تقريرين من نفس النوع');return}const r=await Promise.all(sel.map(i=>api('/api/reports/'+i)));if(r[0].kind!==r[1].kind){alert('اختر تقريرين من نفس النوع');return}r.sort((x,y)=>x.date<y.date?-1:1);$('#cmp').innerHTML=cmpHtml(r[0],r[1])}
</script></body></html>'''

if __name__ == "__main__":
    main()
