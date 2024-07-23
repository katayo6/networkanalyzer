используется Python 3.11.9

доп. библиотеки:

```
matplotlib==3.6.3

networkx==2.8.8

psutil==5.9.8

scapy==2.5.0+git20240324.2b58b51
```

для использования нужно запускать скрипт из-под рута ввиду nmap

### guide:

1) ```pip -r requirements.txt```
   
2) GUI: ```python network_traffic_analysis.py```
   
2.1) Console: `sudo python network_traffic_analysis.py live -i <interface> -f <filters> -t <type> -o <output_file>`

-i, --interface (from "ip a")

-f, --filter (tcp,udp,http,https)

-t, --type: (all, inbound, outbound). default: all

-o, --output: export to pcap file

example:

```sudo python network_traffic_analysis.py live -i wlan0 -f tcp -t all -o new.pcap```

### 3) чтение файла:
   
```python network_traffic_analysis.py pcap -r <pcap_file>```

-r, --read : Путь к pcap-файлу для чтения пакетов.

example:

```python network_traffic_analysis.py pcap -r new.pcap```

### 4) сохранение файла:
   
```python network_traffic_analysis.py save -o <output_file>```

-o, --output :  Имя выходного файла для сохранения логов.

### 5) примеры использования:
    
Захват всех HTTP и HTTPS пакетов на интерфейсе eth0 и сохранение их в файл http_traffic.pcap:
```python network_traffic_analysis.py live -i eth0 -f "port 80 or port 443" -o http_traffic.pcap```

# Чтение пакетов из файла http_traffic.pcap:
```python network_traffic_analysis.py pcap -r http_traffic.pcap```

# Сохранение логов в файл http_logs.txt:
```python network_traffic_analysis.py save -o http_logs.txt```

### Примеры изображений графиков в GUI:

![Alt text](https://github.com/katayo6/networkanalyzer/blob/main/network_graph.png)

