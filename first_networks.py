import re
import socket
import subprocess
import sys
import requests

def is_grey_ip(ip):
    patterns = [
        r'^192\.168\.',
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'
    ]
    return any(re.match(pattern, ip) for pattern in patterns)

def resolve_host(host: str):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Ошибка: не удалось разрешить доменное имя '{host}'")
        print("Возможно нет доступа к интернету")
        return None
    except Exception as e:
        print(f"Неожиданная ошибка при разрешении имени: {str(e)}")
        return None

def get_ip_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,as,isp,query"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return {
                "IP": data.get("query", ip),
                "AS": data.get("as", "N/A").split()[0] if data.get("as") else "N/A",
                "Country": data.get("country", "N/A"),
                "ISP": data.get("isp", "N/A")
            }
    except requests.RequestException:
        pass
    return None

def trace_route(host):
    try:
        command = ["tracert", host]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )
        ips = re.findall(r"\d+\.\d+\.\d+\.\d+", result.stdout)
        return [ip for ip in ips if not is_grey_ip(ip)]
    except Exception as e:
        print(f"\nОшибка при выполнении трассировки: {e}")
        return []

def print_results(host):
    print(f"Трассировка к {host}:")
    header = f"{'№':<5}{'IP':<20}{'AS':<12}{'Страна':<15}{'Провайдер':<30}"
    print("-" * len(header))
    print(header)
    print("-" * len(header))

    ips = trace_route(host)
    if not ips:
        print("Не удалось получить маршрут")
        return

    for i, ip in enumerate(ips, 1):
        info = get_ip_info(ip)
        if not info:
            continue

        print(f"{i:<5}{info['IP']:<20}{info['AS']:<12}"
            f"{info['Country']:<15}{info['ISP']:<30}")



def __main__():
    while True:
        host = input("\nВведите домен/IP (или 'q' для выхода): ").strip()
        if host.lower() == 'q':
            break

        if re.match(r"\d+\.\d+\.\d+\.\d+", host):
            target = host
        else:
            target = resolve_host(host)
            if not target:
                continue

        print_results(target)


if __name__ == '__main__':
    __main__()