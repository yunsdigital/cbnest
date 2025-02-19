# CBNEST Port Scanner

CBNEST, hedef IP veya domain adreslerinin açık portlarını tarayan ve bu portlardaki servisleri inceleyen bir port tarayıcı aracıdır. 
Ayrıca, tespit edilen servislerin güvenlik açıklarını kontrol eder ve HTTP başlık bilgilerini alır.

Not: Sistem sadece PC de çalışmaktadır. Termux desteği bulunmamaktadır.

## Özellikler

- Hedef IP veya domain üzerinde port taraması yapar.
- Açık portları, servis adı ve versiyon bilgilerini gösterir.
- Servislerin güvenlik açıklarını kontrol eder.
- HTTP başlık bilgilerini alır.
- Tarama sonuçlarını bir dosyaya kaydeder.

## Kullanım

Sisteminizde Python ve Nmap yüklü olduğundan emin olun. Yüklemek için:

Python: https://www.python.org/downloads/
Nmap: https://nmap.org/download

Yükleme işleminden sonra dosya yollarını PATH dizinine ekleyin.

PATH değişkenine ekledikten sonra kurulumu kontrol edin. Komut satırına:

python --version
nmap --version

Yazarak kontrol edebilirsiniz. Sürüm numarası veriyorsa kurulum tamamlanmıştır.

Projeyi klonlayın:

git clone https://github.com/yunsdigital/cbnest.git
cd cbnest

Sonrasında modülleri yüklemek için requirements.txt dosyasını kullanın.

pip install -r requirements.txt

Modül yükleme işleminden sonra programı çalıştırın:

python port_scanner.py

Hedef IP veya domain girin ve taramayı başlatın.

Tarama sonucu, açık portlar ve güvenlik açıklarıyla ilgili bilgiler scan_report.txt dosyasına kaydedilir.
