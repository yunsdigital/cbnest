import socket
import requests
import nmap
import time
import os
import threading
import pyfiglet
from tqdm import tqdm
from colorama import Fore, Style, init

os.system('cls' if os.name == 'nt' else 'clear')

init()

ascii_banner = pyfiglet.figlet_format("CBNEST Scanner")
print(Fore.CYAN + ascii_banner + Style.RESET_ALL)

print(Fore.YELLOW + "[+] Gelişmiş Port & Güvenlik Açığı Tarayıcı" + Style.RESET_ALL)
print(Fore.YELLOW + "[+] Geliştirici: yuns.digital" + Style.RESET_ALL)
print(Fore.YELLOW + "[+] Instagram: @yuns.digital" + Style.RESET_ALL)
print("-" * 60)

TARGET = input(Fore.GREEN + "[?] Hedef domain veya IP adresi girin: " + Style.RESET_ALL)

full_scan = input(Fore.GREEN + "[?] Tüm portları taramak ister misiniz? (Evet/Hayır): " + Style.RESET_ALL).strip().lower()
if full_scan == "evet":
    PORTS = range(1, 65535)
else:
    PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]

try:
    nm = nmap.PortScanner()
except nmap.nmap.PortScannerError:
    print(Fore.RED + "[!] Nmap yüklü değil. Nmap yükledikten sonra tekrar deneyin." + Style.RESET_ALL)
    exit()

def get_banner(target, port):
    """ Açık portlardan banner bilgisi almaya çalışır. """
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner if banner else "Belirlenemedi"
    except:
        return "Bilgi alınamadı"

def get_http_headers(target, port):
    """ HTTP servislerinden başlık bilgisi çeker. """
    try:
        url = f"http://{target}:{port}"
        response = requests.get(url, timeout=3)
        return dict(response.headers)
    except requests.RequestException:
        return "Başlıklar alınamadı"

def scan_port(target, port, open_ports):
    """ Port taraması yapar ve servis bilgilerini toplar. """
    try:
        nm.scan(target, str(port), arguments="-A")  # Daha fazla bilgi alır
        if target in nm.all_hosts() and port in nm[target]['tcp']:
            state = nm[target]['tcp'][port]['state']
            service = nm[target]['tcp'][port]['name']
            version = nm[target]['tcp'][port].get('version', 'Bilinmiyor')

            if state == "open":
                banner = get_banner(target, port)
                http_headers = get_http_headers(target, port) if service == "http" else None
                open_ports[port] = (service, version, banner, http_headers)
                print(Fore.RED + f"[!] {port} açık - {service} {version} (Banner: {banner})" + Style.RESET_ALL)
    except Exception:
        pass

def scan_ports(target):
    """ Açık portları tespit eder ve sonuçları döndürür. """
    open_ports = {}
    print(Fore.CYAN + f"\n[+] {target} için port taraması başlatıldı..." + Style.RESET_ALL)
    start_time = time.time()

    threads = []
    for port in PORTS:
        t = threading.Thread(target=scan_port, args=(target, port, open_ports))
        threads.append(t)
        t.start()

    for t in tqdm(threads, desc="Port Tarama"):
        t.join()

    scan_time = round(time.time() - start_time, 2)
    print(Fore.YELLOW + f"\n[+] Tarama tamamlandı! Süre: {scan_time} saniye" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[+] Açık port sayısı: {len(open_ports)}" + Style.RESET_ALL)
    print("-" * 60)

    return open_ports

def check_vulnerabilities(service, version):
    """ NVD API üzerinden CVE taraması yapar. """
    API_URL = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service}+{version}"

    try:
        response = requests.get(API_URL, timeout=5)
        data = response.json()
        if "CVE_Items" in data and len(data["CVE_Items"]) > 0:
            return Fore.RED + f"[!] {service} {version} için güvenlik açıkları olabilir! Daha fazla bilgi: {API_URL}" + Style.RESET_ALL
        else:
            return Fore.GREEN + f"[+] {service} {version} için bilinen zaafiyet bulunamadı." + Style.RESET_ALL
    except:
        return Fore.YELLOW + f"[-] {service} {version} için CVE kontrolü yapılamadı." + Style.RESET_ALL

if __name__ == "__main__":
    try:
        ip_address = socket.gethostbyname(TARGET)
        print(Fore.YELLOW + f"\n[+] {TARGET} IP adresi: {ip_address}" + Style.RESET_ALL)
        print("-" * 60)
    except:
        print(Fore.RED + "[-] Hedef çözümlenemedi!" + Style.RESET_ALL)
        exit()

    open_ports = scan_ports(ip_address)

    # Açık portlardaki servislerde zafiyet olup olmadığını kontrol et ve raporla
    report = []
    for port, (service, version, banner, http_headers) in open_ports.items():
        print(Fore.CYAN + f"[+] {port} numaralı portta çalışan {service} {version} servisi kontrol ediliyor..." + Style.RESET_ALL)
        vuln_result = check_vulnerabilities(service, version)
        print(vuln_result)

        # HTTP başlık bilgisi varsa ekle
        if http_headers:
            print(Fore.YELLOW + f"[+] {port} için HTTP başlıkları: {http_headers}" + Style.RESET_ALL)
            report.append(f"{port}: {service} {version} - {vuln_result} - Banner: {banner} - Headers: {http_headers}")
        else:
            report.append(f"{port}: {service} {version} - {vuln_result} - Banner: {banner}")

    # Sonuçları dosyaya kaydet
    with open("scan_report.txt", "w") as f:
        f.write("\n".join(report))

    print(Fore.YELLOW + "\n[+] Tarama tamamlandı. Rapor 'scan_report.txt' dosyasına kaydedildi." + Style.RESET_ALL)
