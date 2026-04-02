**# rule-based-detection-**

**👾 Description****
A rule-based Intrusion Detection System (IDS) with:
  1. Packet capture
  2. Log parsing
  3. Rule-based detection
  4. Alert generation
  5. GUI dashboard
  6. IP → Process investigation (PID + process mapping)

**🚀 Installation & Setup****

Clone or download project : run the following command 
_git clone https://github.com/Areeba13y/rule-based-detection-_
cd to directory where downloaded

1️⃣ Install Dependencies
pip install scapy
pip install psutil

2️⃣ Run the Script
Windows : Open cmd and cd to project and then run
_python gui.py_

Linux / Mac:
sudo python gui.py

**🧠 System Architecture**
capture.py  → captures packets → logs.json  
engine.py   → analyzes logs → alerts.txt  
gui.py      → visual interface + investigation  
psutil      → maps connections → processes  

**🧪 Testing the System**
1. Run the program
<img width="1197" height="787" alt="image" src="https://github.com/user-attachments/assets/9b9df33e-20c8-4cd6-b8e5-37edf97ccdd0" />
2. Start capturing packets
<img width="1197" height="785" alt="image" src="https://github.com/user-attachments/assets/6e464e26-137e-4a6d-b9c4-ad0484f54b99" />
3. Run detection
<img width="1198" height="787" alt="image" src="https://github.com/user-attachments/assets/a502ba78-ffee-4999-a962-1da28e55374c" />
4. Investigate ips
<img width="1196" height="247" alt="image" src="https://github.com/user-attachments/assets/7033ffc5-bebb-4f47-ae48-307567ed83df" />
5. You can also Clear Logs and Refresh to capture fresh packets.

