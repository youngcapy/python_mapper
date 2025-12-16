#!/usr/bin/env python3
import json
import datetime
import nmap3
import psycopg2
import ipaddress
import socket
# в начало файла добавь:
import os
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.offsetbox import OffsetImage, AnnotationBbox

SYSLOG_SERVER = "172.0.15.110"
SYSLOG_PORT = 514
NETWORK_CIDR = "192.168.1.0/24"
JSON_OUT = "E:/coursework/network_topology.json"
SYSLOG_OUT = "E:/coursework/network_topology.log"   # файл для SIEM

PG_CONN = {
    "host": "127.0.0.1",
    "port": 5432,
    "dbname": "linktelligence",
    "user": "postgres",
    "password": "admin"
}

IMAGE_OUT = "E:/coursework/network_topology.png"

# Путь к иконкам (по желанию). Если файлов нет, будут просто цветные узлы.
ICON_DIR = "E:/coursework/icons"  # printer.png, router.png, firewall.png, endpoint.png

NODE_COLORS = {
    "router":   "#ff7f0e",
    "firewall": "#d62728",
    "printer":  "#2ca02c",
    "endpoint": "#1f77b4",
}

def load_icon(node_type, zoom=0.1):
    """
    Пытается загрузить PNG-иконку для типа узла.
    Если файла нет, возвращает None (будет стандартный кружок).
    """
    fname = os.path.join(ICON_DIR, f"{node_type}.png")
    if not os.path.exists(fname):
        return None
    img = plt.imread(fname)
    return OffsetImage(img, zoom=zoom)


def draw_topology(topology, path):
    """
    Рисует граф: узлы с подписями IP, связи из topology["links"].
    В файл path сохраняется PNG.
    """
    G = nx.Graph()

    # Добавляем только узлы с хотя бы одним открытым портом
    for node in topology["nodes"]:
        if node["open_port_count"] == 0:
            continue
        G.add_node(node["id"], type=node["type"], ports=node["open_ports"])

    # Добавляем рёбра
    for link in topology["links"]:
        s = link["source"]
        t = link["target"]
        if s in G.nodes and t in G.nodes:
            G.add_edge(s, t)

    if len(G.nodes) == 0:
        print("Нет узлов с открытыми портами — нечего рисовать")
        return

    # Вычисляем координаты вершин (spring layout)
    pos = nx.spring_layout(G, k=0.7, iterations=100)

    fig, ax = plt.subplots(figsize=(10, 8))
    ax.set_axis_off()

    # Сначала рисуем рёбра
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#999999", width=1.0)

    # Узлы + подписи
    for node_id, (x, y) in pos.items():
        ntype = G.nodes[node_id].get("type", "endpoint")

        icon = load_icon(ntype)
        if icon is not None:
            ab = AnnotationBbox(icon, (x, y), frameon=False)
            ax.add_artist(ab)
        else:
            # Цветные кружки, если нет иконок
            ax.scatter(
                [x], [y],
                s=800,
                c=NODE_COLORS.get(ntype, "#1f77b4"),
                edgecolors="black",
                zorder=3
            )

        # Подпись IP-адреса
        ax.text(
            x, y - 0.06, node_id,
            ha="center", va="top",
            fontsize=8, color="black"
        )

    plt.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)



def detect_node_type(ports):
    pset = set(ports)

    # Принтер
    if 9100 in pset or 515 in pset or 631 in pset:
        return "printer"

    # Маршрутизатор / L3‑устройство
    if any(p in pset for p in (179, 161, 23)):
        return "router"

    # Файрвол
    if any(p in pset for p in (514, 443, 80)) and 22 in pset:
        return "firewall"

    return "endpoint"

def scan_network(cidr):
    # более агрессивный TCP‑скан
    nmap = nmap3.NmapScanTechniques()
    port_results = nmap.nmap_syn_scan(
        cidr,
        args="-p 1-1024,2222,3389 -sV -Pn"
    )

    nodes = []
    for ip, pdata in port_results.items():
        if not isinstance(pdata, dict):
            continue
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            continue

        ports = []
        for p in pdata.get("ports", []):
            if p.get("state") == "open":
                try:
                    ports.append(int(p["portid"]))
                except (KeyError, ValueError, TypeError):
                    continue

        node = {
            "id": ip,
            "ip_obj": ip_obj,          # чтобы не пересчитывать
            "type": detect_node_type(ports),
            "open_ports": ports,
            "open_port_count": len(ports)
        }
        nodes.append(node)

    # --- формирование связей ---
    links = []
    if nodes:
        # подсеть всего скана
        net = ipaddress.ip_network(cidr, strict=False)

        # роутеры в этой подсети
        routers = [n for n in nodes if n["type"] == "router" and n["ip_obj"] in net]

        # если роутеров несколько, используем первый как "главный"
        main_router = routers[0] if routers else None

        for n in nodes:
            if n["open_port_count"] == 0:
                continue
            # соединяем все узлы из подсети с роутером
            if main_router and n["id"] != main_router["id"] and n["ip_obj"] in net:
                links.append({"source": main_router["id"], "target": n["id"]})

    # убираем служебное поле перед возвратом
    for n in nodes:
        n.pop("ip_obj", None)

    return {
        "scan_time": datetime.datetime.utcnow().isoformat() + "Z",
        "nodes": nodes,
        "links": links
    }


def save_json(topology, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(topology, f, indent=2, ensure_ascii=False)

def format_syslog_message(hostname, appname, msg, severity="info"):
    """
    Простейший RFC3164‑подобный формат:
    <PRI>MMM dd HH:MM:SS HOST APP: message
    PRI = facility(1=user)*8 + severity(6=info,5=notice,4=warning,...)
    """
    facility = 1  # user-level messages
    sev_map = {
        "emerg": 0, "alert": 1, "crit": 2, "err": 3,
        "warning": 4, "notice": 5, "info": 6, "debug": 7
    }
    sev = sev_map.get(severity, 6)
    pri = facility * 8 + sev

    now = datetime.datetime.now()
    timestamp = now.strftime("%b %d %H:%M:%S")
    return f"<{pri}>{timestamp} {hostname} {appname}: {msg}"

def write_syslog_log(topology, path):
    """
    Пишем одну строку: время сканирования и количество обнаруженных хостов
    и отправляем её как syslog-пакет на удалённый сервер.
    """
    hostname = socket.gethostname()
    appname = "topology-mapper"

    scan_time = topology["scan_time"]
    host_count = sum(1 for n in topology["nodes"] if n["open_port_count"] > 0)

    msg = (
        f"network_scan_summary hosts={host_count} "
        f"scan_time={scan_time}"
    )
    line = format_syslog_message(hostname, appname, msg, severity="info")

    # 1) локальный лог-файл
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

    # 2) отправка на удалённый syslog-сервер (Wazuh)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(line.encode("utf-8"), (SYSLOG_SERVER, SYSLOG_PORT))
    finally:
        sock.close()


def store_pg(topology):
    scan_date = datetime.datetime.utcnow().strftime("%Y%m%d")
    table = f"network_topology_{scan_date}"

    conn = psycopg2.connect(**PG_CONN)
    cur = conn.cursor()

    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id SERIAL PRIMARY KEY,
            scan_time TIMESTAMPTZ NOT NULL,
            node_ip inet NOT NULL,
            node_type text NOT NULL,
            open_ports integer[] NOT NULL,
            open_port_count integer NOT NULL
        );
    """)

    for node in topology["nodes"]:
        cur.execute(
            f"INSERT INTO {table} (scan_time, node_ip, node_type, open_ports, open_port_count) "
            f"VALUES (%s, %s, %s, %s, %s);",
            (topology["scan_time"], node["id"], node["type"],
             node["open_ports"], node["open_port_count"])
        )

    conn.commit()
    cur.close()
    conn.close()

def main():
    topo = scan_network(NETWORK_CIDR)
    save_json(topo, JSON_OUT)
    write_syslog_log(topo, SYSLOG_OUT)
    store_pg(topo)
    draw_topology(topo, IMAGE_OUT)   # <-- новая строка

if __name__ == "__main__":
    main()
