# 🛰️ Network Full Sniffer
### A Professional Cross‑Platform Network Packet Analyzer with Full Bilingual Support (EN/FA)
### تحلیل‌گر حرفه‌ای بسته‌های شبکه با پشتیبانی کامل دو زبانه (فارسی/انگلیسی)

---

## 📌 About the Project | درباره پروژه

Network Full Sniffer یک ابزار پیشرفته برای **تحلیل بسته‌های شبکه** است که با هدف ارائه‌ی یک محیط حرفه‌ای، دقیق و کاملاً کاربرپسند طراحی شده است.  
این پروژه با توجه به استانداردهای امنیت سایبری و نیاز متخصصان تست نفوذ، توسط **مهدی زبردست برزین** – برنامه‌نویس، متخصص امنیت و مدرس دانشگاه – توسعه یافته است.

This project is built for cybersecurity professionals, penetration testers, and network analysts who require a robust, real‑time, bilingual network packet analysis tool.

---

## ✨ Key Features | قابلیت‌های کلیدی

- **🔹 Packet Capture | ضبط بسته‌ها**: Capture and analyze network packets in real-time.  
  ضبط بسته‌ها به‌صورت زنده و تحلیل دقیق ترافیک شبکه.

- **🔹 Bilingual User Interface | رابط کاربری دو زبانه**: Full support for both English and Persian languages.  
  پشتیبانی کامل از زبان‌های انگلیسی و فارسی.

- **🔹 Advanced Filtering | فیلتر پیشرفته**: Filter packets using BPF (Berkeley Packet Filter) syntax.  
  امکان فیلتر حرفه‌ای بسته‌ها با استفاده از سینتکس BPF.

- **🔹 Protocol Analysis | تحلیل پروتکل‌ها**: Detailed info for TCP, UDP, ICMP, HTTP, DNS, and more.  
  نمایش جزئیات پروتکل‌های مختلف شبکه شامل TCP، UDP، ICMP، HTTP، DNS و غیره.

- **🔹 Real-time Statistics | آمار لحظه‌ای**: Monitor live network traffic statistics.  
  مشاهده لحظه‌ای آمار و جریان ترافیک شبکه.

- **🔹 Interactive Graphs | نمودارهای تعاملی**: Visualize network traffic with interactive charts.  
  ارائه نمودارهای تعاملی برای تحلیل و بررسی شبکه.

---

## ⚙️ Requirements | نیازمندی‌ها

- Python 3.8 or higher  
- Windows, Linux, or macOS  
- Administrator/root privileges (for packet capture)  

---

## 💻 Installation | نصب

1. Clone the repository:
   ```bash
   git clone https://github.com/mahdizebardastbarzin/network-full-sniffer.git
   cd network-full-sniffer
   ```

2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Additional dependencies (Linux/macOS):
   ```bash
   # Debian/Ubuntu
   sudo apt-get install libpcap-dev

   # CentOS/RHEL
   sudo yum install libpcap-devel

   # macOS (Homebrew)
   brew install libpcap
   ```

---

## 🚀 Usage | نحوه استفاده

1. Run the application:
   ```bash
   python main.py
   ```

2. Select a network interface from the dropdown menu.  
3. (Optional) Enter a BPF filter expression (e.g., `tcp port 80`).  
4. Click "Start" to begin capturing packets.  
5. Use the tabs to switch between different views (Packets, Statistics, Graphs).

---

## 📸 Screenshots | تصاویر

*(Screenshots will be added in future updates)*  
*(تصاویر در به‌روزرسانی‌های بعدی اضافه خواهند شد)*

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](https://github.com/mahdizebardastbarzin/mahdizebardastbarzin/blob/main/CONTRIBUTING.md) to get started.

## 🤝 مشارکت

مشارکت‌های شما خوش‌آمد است! لطفاً [راهنمای مشارکت](https://github.com/mahdizebardastbarzin/mahdizebardastbarzin/blob/main/CONTRIBUTING.md) را مطالعه کنید.
 
هرگونه مشارکت و توسعه خوش‌آمد است! لطفاً Pull Request ارسال کنید.

---

## 📄 License | مجوز

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.  
این پروژه تحت مجوز MIT منتشر شده است – برای جزئیات فایل [LICENSE](LICENSE) را مشاهده کنید.

---

## 🙏 Acknowledgments | قدردانی

- Built with [PyQt6](https://www.riverbankcomputing.com/software/pyqt/)  
- Uses [Scapy](https://scapy.net/) for packet manipulation  
- Icons from [Material Design Icons](https://materialdesignicons.com/)  

---

## ⚠️ Note for Windows Users | توجه برای کاربران ویندوز

You may need to install Npcap or WinPcap for packet capture on Windows. Download it from [Npcap](https://npcap.com/).  

برای ضبط بسته‌ها در ویندوز، ممکن است نیاز به نصب Npcap یا WinPcap داشته باشید. می‌توانید آن را از [اینجا](https://npcap.com/) دانلود کنید.
