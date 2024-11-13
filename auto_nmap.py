import nmap
import os

# Función para mostrar el banner del programa
def show_banner():
    banner = """
    █████╗ ██╗   ██╗████████╗ ██████╗     ███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
   ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ████╗  ██║████╗ ████║██╔══██╗██╔══██╗
   ███████║██║   ██║   ██║   ██║   ██║    ██╔██╗ ██║██╔████╔██║███████║██████╔╝
   ██╔══██║██║   ██║   ██║   ██║   ██║    ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
   ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
   ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     

                        Herramienta de escaneo automático
                             Creado por: Gonka79
    """
    print(banner)
# Función para exportar resultados del escaneo
def export_scan_results(nm, filename, export_format):
    """
    Exporta los resultados del escaneo en el formato seleccionado.
    """
    if export_format == "txt":
        with open(f"{filename}.txt", "w") as file:
            file.write(nm.csv())
        print(f"Resultados exportados a {filename}.txt")

    elif export_format == "xml":
        nm.write_xml(f"{filename}.xml")
        print(f"Resultados exportados a {filename}.xml")

    elif export_format == "json":
        with open(f"{filename}.json", "w") as file:
            file.write(nm.get_nmap_last_output())
        print(f"Resultados exportados a {filename}.json")

    else:
        print("Formato de exportación no válido.")

# Función principal
def main():
    show_banner()  # Llama al banner dentro de la función `main()`.

# Punto de entrada del script
if __name__ == "__main__":
    main()

# Función para exportar resultados después de cualquier escaneo
def prompt_export_results(nm):
    export = input("¿Deseas exportar los resultados del escaneo? (s/n): ").lower()
    if export == 's':
        export_format = input("Elige el formato de exportación (txt/xml/json): ").lower()
        filename = input("Introduce el nombre del archivo para guardar los resultados: ")
        export_scan_results(nm, filename, export_format)

# Sector 1: Escaneo básico (TCP, UDP o ambos)
def scan_basic(ip, options):
    nm = nmap.PortScanner()
    
    # Preguntar si el usuario quiere escanear TCP, UDP o ambos
    scan_tcp = input("¿Quieres realizar un escaneo TCP? (s/n): ").lower() == 's'
    scan_udp = input("¿Quieres realizar un escaneo UDP? (s/n): ").lower() == 's'
    
    if not scan_tcp and not scan_udp:
        print("No se seleccionó ningún escaneo. Saliendo del escaneo básico.")
        return

    # Si se selecciona solo el ping scan
    if options.get('ping_scan'):
        scan_arguments = '-sn -vv --privileged'
        print(f"Iniciando ping scan en {ip}...")
        nm.scan(ip, arguments=scan_arguments.strip())
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                print(f"Host detectado: {host} ({nm[host].hostname()})")

    else:
        print("Se escanearán los 1000 puertos más importantes.")
        
        # Escaneo TCP
        if scan_tcp:
            scan_arguments_tcp = '--top-ports 1000 -sS -Pn -vv --privileged'
            if options.get('os_detection') or options.get('service_version'):
                scan_arguments_tcp += ' -A'
            print(f"Iniciando escaneo TCP en {ip}...")
            nm.scan(ip, arguments=scan_arguments_tcp.strip())
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    print(f"\nHost: {host} ({nm[host].hostname()})")
                    for proto in nm[host].all_protocols():
                        if proto == 'tcp':
                            print("\nProtocolo: tcp")
                            ports = nm[host][proto].keys()
                            for port in ports:
                                state = nm[host][proto][port]['state']
                                print(f"Puerto: {port}\tEstado: {state}")
                                if 'product' in nm[host][proto][port]:
                                    product = nm[host][proto][port]['product']
                                    version = nm[host][proto][port].get('version', '')
                                    print(f"Servicio: {product} {version}")

        # Escaneo UDP
        if scan_udp:
            scan_arguments_udp = '--top-ports 1000 -sU -T4 --max-retries 1 -vv'
            print(f"Iniciando escaneo UDP en {ip}...")
            nm.scan(ip, arguments=scan_arguments_udp.strip())
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    print(f"\nHost: {host} ({nm[host].hostname()})")
                    for proto in nm[host].all_protocols():
                        if proto == 'udp':
                            print("\nProtocolo: udp")
                            ports = nm[host][proto].keys()
                            for port in ports:
                                state = nm[host][proto][port]['state']
                                print(f"Puerto: {port}\tEstado: {state}")
    
    # Exportar resultados
    prompt_export_results(nm)


# Sector 2: Escaneo avanzado TCP
def scan_tcp_ports(ip, options):
    nm = nmap.PortScanner()
    print("Se escanearán todos los puertos TCP (1-65535).")
    scan_arguments = '-p 1-65535 -sS -T4 -vv'
    if options.get('service_version'):
        scan_arguments += ' -sV'
    if options.get('os_detection'):
        scan_arguments += ' -O'
    if options.get('traceroute'):
        scan_arguments += ' --traceroute'
    if options.get('version_intensity'):
        scan_arguments += f" --version-intensity {options['version_intensity']}"
    if options.get('timeout'):
        scan_arguments += f" --host-timeout {options['timeout']}"
    if options.get('scan_speed'):
        scan_arguments += f" -T{options['scan_speed']}"
    print(f"Iniciando escaneo TCP avanzado en {ip}...")
    nm.scan(ip, arguments=scan_arguments.strip())
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            print(f"\nHost: {host} ({nm[host].hostname()})")
            for proto in nm[host].all_protocols():
                print(f"\nProtocolo: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    print(f"Puerto: {port}\tEstado: {nm[host][proto][port]['state']}")
                    if 'product' in nm[host][proto][port]:
                        print(f"Servicio: {nm[host][proto][port]['product']} {nm[host][proto][port]['version']}")
    
    # Exportar resultados
    prompt_export_results(nm)

# Sector 3: Escaneo avanzado UDP
def scan_udp_ports(ip):
    nm = nmap.PortScanner()
    print("Se escanearán los 1000 puertos UDP más importantes.")
    scan_arguments = '--top-ports 1000 -sU -T4 --max-retries 1 -vv'
    print(f"Iniciando escaneo UDP en {ip}...")
    nm.scan(ip, arguments=scan_arguments.strip())
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            print(f"\nHost: {host} ({nm[host].hostname()})")
            for proto in nm[host].all_protocols():
                print(f"\nProtocolo: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    print(f"Puerto: {port}\tEstado: {nm[host][proto][port]['state']}")
    
    # Exportar resultados
    prompt_export_results(nm)


# Sector 4: Escaneo con scripts NSE organizados por categoría
NSE_SCRIPTS = {
    "auth": [
        {"name": "ssh-auth-methods", "description": "Enumera los métodos de autenticación habilitados en el servidor SSH."},
        {"name": "smb-enum-users", "description": "Enumera usuarios del servicio SMB."},
        {"name": "ftp-anon", "description": "Verifica si el servidor FTP permite acceso anónimo."},
        {"name": "imap-capabilities", "description": "Obtiene capacidades del servidor IMAP."},
        {"name": "smtp-enum-users", "description": "Enumera usuarios del servidor SMTP."},
        {"name": "pop3-capabilities", "description": "Obtiene capacidades del servidor POP3."},
        {"name": "ssl-cert", "description": "Obtiene el certificado SSL del servidor."},
        {"name": "http-auth-finder", "description": "Busca páginas web que requieren autenticación HTTP."},
        {"name": "http-auth", "description": "Prueba diferentes métodos de autenticación HTTP."}
    ],
    "brute": [
        {"name": "ssh-brute", "description": "Ataque de fuerza bruta a servidores SSH."},
        {"name": "ftp-brute", "description": "Ataque de fuerza bruta a servidores FTP."},
        {"name": "http-brute", "description": "Ataque de fuerza bruta a servicios HTTP."},
        {"name": "smtp-brute", "description": "Ataque de fuerza bruta al servidor SMTP."},
        {"name": "telnet-brute", "description": "Ataque de fuerza bruta a servidores Telnet."},
        {"name": "imap-brute", "description": "Ataque de fuerza bruta al servidor IMAP."},
        {"name": "pop3-brute", "description": "Ataque de fuerza bruta al servidor POP3."},
        {"name": "mysql-brute", "description": "Ataque de fuerza bruta a servidores MySQL."},
        {"name": "snmp-brute", "description": "Ataque de fuerza bruta al servicio SNMP."}
    ],
    "discovery": [
        {"name": "dns-brute", "description": "Realiza fuerza bruta en DNS para encontrar subdominios."},
        {"name": "snmp-info", "description": "Obtiene información del servicio SNMP."},
        {"name": "ldap-rootdse", "description": "Obtiene información básica del servidor LDAP."},
        {"name": "nbstat", "description": "Obtiene información del servicio NetBIOS."},
        {"name": "mdns-discovery", "description": "Descubre servicios mediante mDNS."},
        {"name": "ntp-info", "description": "Obtiene información del servidor NTP."},
        {"name": "smb-os-discovery", "description": "Detecta información del sistema operativo usando SMB."},
        {"name": "http-enum", "description": "Enumera recursos web comunes en el servidor HTTP."},
        {"name": "broadcast-ping", "description": "Envía ping de broadcast para descubrir hosts activos en la red."}
    ],
 
    "default": [
        {"name": "ssl-enum-ciphers", "description": "Enumera los cifrados SSL/TLS permitidos en el servidor."},
        {"name": "http-title", "description": "Obtiene el título de la página web."},
        {"name": "banner", "description": "Obtiene el banner del servicio."},
        {"name": "whois-domain", "description": "Realiza una consulta WHOIS para obtener información de dominio."},
        {"name": "ftp-anon", "description": "Verifica si el servidor FTP permite acceso anónimo."},
        {"name": "dns-service-discovery", "description": "Descubre servicios DNS disponibles."},
        {"name": "http-methods", "description": "Detecta métodos HTTP habilitados en el servidor."}
    ],
    "dos": [
        {"name": "http-slowloris-check", "description": "Verifica si el servidor es vulnerable a ataques Slowloris."},
        {"name": "smtp-vuln-cve2011-1720", "description": "Detecta vulnerabilidad de DoS en servidores SMTP (CVE-2011-1720)."},
        {"name": "ntp-monlist", "description": "Prueba si el servidor NTP permite ataques de amplificación con 'monlist'."},
        {"name": "snmp-dos", "description": "Intenta un ataque de denegación de servicio al servicio SNMP."},
        {"name": "sshv1", "description": "Detecta si el servidor SSH permite conexiones inseguras con SSHv1."}
    ],
    "exploit": [
        {"name": "smb-vuln-ms17-010", "description": "Detecta vulnerabilidad EternalBlue en SMB (CVE-2017-0144)."},
        {"name": "http-shellshock", "description": "Detecta vulnerabilidad Shellshock en servidores HTTP."},
        {"name": "ftp-proftpd-backdoor", "description": "Detecta backdoor en servidores ProFTPd."},
        {"name": "mysql-vuln-cve2012-2122", "description": "Detecta vulnerabilidad en servidores MySQL (CVE-2012-2122)."},
        {"name": "rmi-vuln-classloader", "description": "Detecta vulnerabilidad de ejecución remota en servidores RMI."},
        {"name": "ms-sql-xp-cmdshell", "description": "Prueba la ejecución remota de comandos en servidores MS SQL usando xp_cmdshell."}
    ],
    "external": [
        {"name": "shodan-api", "description": "Obtiene información del host usando la API de Shodan."},
        {"name": "whois-ip", "description": "Consulta WHOIS para obtener información sobre la dirección IP."},
        {"name": "ip-geolocation-geoplugin", "description": "Obtiene información de geolocalización usando GeoPlugin."},
        {"name": "ip-geolocation-ipinfodb", "description": "Obtiene información de geolocalización usando IPInfoDB."},
        {"name": "virustotal", "description": "Obtiene información del archivo usando la API de VirusTotal."}
    ],
    "fuzzer": [
        {"name": "http-fuzz", "description": "Realiza pruebas de fuzzing en servidores HTTP."},
        {"name": "smtp-fuzz", "description": "Realiza pruebas de fuzzing en servidores SMTP."},
        {"name": "snmp-fuzz", "description": "Realiza pruebas de fuzzing en el servicio SNMP."},
        {"name": "dns-fuzz", "description": "Realiza pruebas de fuzzing en servidores DNS."},
        {"name": "ftp-fuzz", "description": "Realiza pruebas de fuzzing en servidores FTP."}
    ],
    "intrusive": [
        {"name": "smb-brute", "description": "Ataque de fuerza bruta al servicio SMB."},
        {"name": "http-sql-injection", "description": "Intenta realizar ataques de inyección SQL en servidores HTTP."},
        {"name": "rdp-vuln-ms12-020", "description": "Detecta vulnerabilidad MS12-020 en servidores RDP."},
        {"name": "smtp-open-relay", "description": "Prueba si el servidor SMTP permite relay abierto."},
        {"name": "telnet-encryption", "description": "Detecta si el servidor Telnet usa cifrado débil."}
    ],
     "malware": [
        {"name": "http-malware-host", "description": "Detecta malware en el host HTTP."},
    {"name": "malware-checker", "description": "Verifica la presencia de malware usando firmas conocidas."},
    {"name": "smb-vuln-conficker", "description": "Detecta la vulnerabilidad Conficker en el servicio SMB."},
    {"name": "http-zeustracker", "description": "Verifica si el host está listado en el Zeus Tracker."},
    {"name": "smtp-vuln-cve2011-1764", "description": "Detecta vulnerabilidad de malware en servidores SMTP (CVE-2011-1764)."},
    {"name": "http-phpself-xss", "description": "Detecta posibles vulnerabilidades de malware mediante XSS en PHP_SELF."},
    {"name": "dns-zone-transfer", "description": "Verifica si el servidor DNS permite transferencias de zona que podrían ser usadas para propagar malware."},
    {"name": "ftp-proftpd-backdoor", "description": "Detecta una puerta trasera en servidores ProFTPd infectados con malware."},
    {"name": "maltrail-detection", "description": "Verifica si el host está presente en bases de datos de tráfico sospechoso de Maltrail."},
    {"name": "sip-malware-check", "description": "Detecta patrones de malware en servidores SIP."},
    {"name": "imap-malware-scanner", "description": "Escanea mensajes IMAP en busca de patrones de malware."},
    {"name": "http-slowloris-check", "description": "Verifica si el servidor HTTP es vulnerable a ataques Slowloris, frecuentemente usados por malware."}
    ],
    "safe": [
        {"name": "ssl-enum-ciphers", "description": "Enumera los cifrados SSL/TLS permitidos en el servidor."},
        {"name": "http-title", "description": "Obtiene el título de la página web."},
        {"name": "banner", "description": "Obtiene el banner del servicio."},
        {"name": "whois-domain", "description": "Realiza una consulta WHOIS para obtener información de dominio."},
        {"name": "uptime", "description": "Obtiene el tiempo de actividad del sistema."},
        {"name": "dns-service-discovery", "description": "Descubre servicios DNS disponibles en la red."}
    ],
    "version": [
        {"name": "ssh-hostkey", "description": "Obtiene la clave pública del servidor SSH."},
        {"name": "ftp-syst", "description": "Obtiene información del sistema del servidor FTP."},
        {"name": "smtp-commands", "description": "Enumera los comandos disponibles en el servidor SMTP."},
        {"name": "pop3-ntlm-info", "description": "Obtiene información NTLM del servidor POP3."},
        {"name": "imap-ntlm-info", "description": "Obtiene información NTLM del servidor IMAP."},
        {"name": "ssl-cert", "description": "Obtiene el certificado SSL del servidor."}
    ], 
    "broadcast": [
    {"name": "broadcast-ping", "description": "Envía ping de broadcast para descubrir hosts activos en la red."},
    {"name": "broadcast-dhcp-discover", "description": "Envía solicitudes DHCP para descubrir servidores DHCP en la red."},
    {"name": "broadcast-netbios-master-browser", "description": "Detecta el servidor NetBIOS principal en la red."},
    {"name": "broadcast-igmp-discovery", "description": "Detecta hosts activos mediante IGMP."},
    {"name": "broadcast-ospf2-discover", "description": "Detecta routers OSPF en la red mediante multicast."},
    {"name": "broadcast-wpad-discover", "description": "Detecta configuraciones WPAD en la red."},
    {"name": "broadcast-ms-sql-discover", "description": "Detecta instancias de Microsoft SQL Server en la red."},
    {"name": "broadcast-novell-locate", "description": "Detecta servicios Novell en la red usando multicast."},
    {"name": "broadcast-eigrp-discovery", "description": "Descubre routers EIGRP en la red."},
    {"name": "broadcast-hid-discoveryd", "description": "Detecta dispositivos HID (Human Interface Device) en la red."}
    ],
    "vuln": [
    {"name": "smb-vuln-ms08-067", "description": "Detecta la vulnerabilidad MS08-067 en SMB."},
    {"name": "smb-vuln-ms17-010", "description": "Detecta la vulnerabilidad EternalBlue en SMB (CVE-2017-0144)."},
    {"name": "http-vuln-cve2011-3368", "description": "Detecta la vulnerabilidad CVE-2011-3368 en servidores HTTP."},
    {"name": "ssl-heartbleed", "description": "Detecta la vulnerabilidad Heartbleed en SSL."},
    {"name": "vulners", "description": "Detecta vulnerabilidades conocidas usando la base de datos de Vulners."},
    {"name": "ftp-vuln-cve2010-4221", "description": "Detecta la vulnerabilidad en servidores FTP (CVE-2010-4221)."},
    {"name": "http-vuln-cve2017-5638", "description": "Detecta la vulnerabilidad CVE-2017-5638 en servidores HTTP."},
    {"name": "smb-vuln-conficker", "description": "Detecta la vulnerabilidad Conficker en el servicio SMB."},
    {"name": "http-vuln-misfortune-cookie", "description": "Detecta la vulnerabilidad Misfortune Cookie en servidores HTTP."},
    {"name": "rdp-vuln-ms12-020", "description": "Detecta la vulnerabilidad MS12-020 en servidores RDP."},
    {"name": "http-vuln-cve2013-7091", "description": "Detecta la vulnerabilidad CVE-2013-7091 en servidores HTTP."},
    {"name": "smtp-vuln-cve2011-1720", "description": "Detecta la vulnerabilidad de DoS en servidores SMTP (CVE-2011-1720)."}
],
}
CATEGORY_DESCRIPTIONS = {
    "auth": "Scripts relacionados con autenticación y métodos de acceso.",
    "brute": "Scripts para ataques de fuerza bruta.",
    "discovery": "Scripts para la detección de servicios y hosts en la red.",
    "default": "Scripts que se ejecutan automáticamente con la opción -sC de Nmap.",
    "dos": "Scripts para pruebas de denegación de servicio (DoS).",
    "exploit": "Scripts que intentan explotar vulnerabilidades conocidas.",
    "external": "Scripts que requieren servicios externos para obtener información adicional.",
    "fuzzer": "Scripts para pruebas de fuzzing, que envían datos inesperados a los servicios.",
    "intrusive": "Scripts intrusivos que pueden afectar la estabilidad del sistema.",
    "malware": "Scripts para la detección de malware en servicios y dispositivos.",
    "safe": "Scripts seguros que se pueden ejecutar sin riesgos.",
    "version": "Scripts para la detección de versiones de servicios.",
    "broadcast": "Scripts para escaneos de red multicast y broadcast.",
    "vuln": "Scripts para la detección de vulnerabilidades conocidas."
}


# Función para mostrar las categorías disponibles
def display_nse_categories():
    print("Categorías de scripts NSE disponibles:")
    print("0. Volver al menú principal")
    for idx, category in enumerate(NSE_SCRIPTS.keys(), 1):
        print(f"{idx}. {category}: {CATEGORY_DESCRIPTIONS.get(category, 'Sin descripción')}")

# Función para mostrar los scripts dentro de una categoría seleccionada
def display_nse_scripts(category):
    """
    Muestra la lista de scripts disponibles en la categoría seleccionada.
    """
    print(f"\nScripts disponibles en la categoría '{category}':")
    print("0. Volver al menú de categorías")
    scripts = NSE_SCRIPTS[category]
    for idx, script in enumerate(scripts, 1):
        print(f"{idx}. {script['name']}: {script['description']}")

def scan_nse_scripts(ip):
    nm = nmap.PortScanner()

    while True:
        # Mostrar categorías y permitir volver al menú principal
        display_nse_categories()
        try:
            category_idx = int(input("\nSelecciona una categoría de scripts NSE (número, 0 para salir): ")) - 1
            category_list = list(NSE_SCRIPTS.keys())
            if category_idx == -1:
                print("Volviendo al menú principal...")
                return  # Salir de la función y volver al menú principal
            if category_idx < 0 or category_idx >= len(category_list):
                print("Categoría no válida.")
                continue
            category = category_list[category_idx]
        except ValueError:
            print("Entrada no válida.")
            continue

        while True:
            # Mostrar scripts dentro de la categoría seleccionada
            display_nse_scripts(category)
            seleccion = input("\nSelecciona los números de los scripts que deseas aplicar (separados por comas, 0 para volver): ")

            # Volver al menú de categorías si el usuario elige 0
            if seleccion == '0':
                print("Volviendo al menú de categorías...")
                break

            try:
                scripts = NSE_SCRIPTS[category]
                scripts_seleccionados = [scripts[int(num) - 1]["name"] for num in seleccion.split(",") if 0 < int(num) <= len(scripts)]
            except (ValueError, IndexError):
                print("Selección no válida.")
                continue

            if scripts_seleccionados:
                scan_arguments = f'-p 1-65535 -vv --script={",".join(scripts_seleccionados)}'
            else:
                print("No se seleccionaron scripts NSE.")
                continue

            scan_speed = input("Elige la velocidad del escaneo (1-lento, 5-rápido): ") or '4'
            scan_arguments += f" -T{scan_speed}"

            host_timeout = input("¿Quieres establecer un límite de tiempo para el host? (Ejemplo: 60s o 5m): ")
            if host_timeout:
                scan_arguments += f" --host-timeout {host_timeout}"

            print(f"Iniciando escaneo con scripts NSE en {ip}...")

            try:
                nm.scan(ip, arguments=scan_arguments.strip())
            except Exception as e:
                print(f"Error al ejecutar el escaneo: {e}")
                return

            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    print(f"\nHost: {host} ({nm[host].hostname()})")
                    for proto in nm[host].all_protocols():
                        print(f"\nProtocolo: {proto}")
                        ports = nm[host][proto].keys()
                        for port in ports:
                            print(f"Puerto: {port}\tEstado: {nm[host][proto][port]['state']}")
                            script_results = nm[host][proto][port].get('script', {})
                            if script_results:
                                print("Resultados de scripts:")
                                for script_name, result in script_results.items():
                                    print(f" - {script_name}: {result}")
                            else:
                                print("No se encontraron resultados de scripts para este puerto.")
                                
                        
# Sector 5: Menú principal y selección de escaneo
def main():
    ip = input("Introduce la IP o el rango de IPs a escanear (Ejemplos: 192.168.1.1, 192.168.0.100-150, 192.168.1.0/24): ")

    scan_type = input("¿Qué tipo de escaneo quieres? (b para básico / a para avanzado / s para scripts NSE): ").lower()

    if scan_type == 'b':
        options = {}
        options['ping_scan'] = input("¿Quieres hacer solo un ping scan (sin escanear puertos)? (s/n): ").lower() == 's'

        if not options['ping_scan']:
            options['os_detection'] = input("¿Quieres intentar detectar el sistema operativo? (s/n): ").lower() == 's'
            options['service_version'] = input("¿Quieres detectar la versión de los servicios TCP? (s/n): ").lower() == 's'

        scan_basic(ip, options)

    elif scan_type == 'a':
        options = {}
        options['service_version'] = input("¿Quieres detectar la versión de los servicios TCP? (s/n): ").lower() == 's'
        options['os_detection'] = input("¿Quieres intentar detectar el sistema operativo? (s/n): ").lower() == 's'
        options['traceroute'] = input("¿Quieres hacer un traceroute al host? (s/n): ").lower() == 's'
        options['version_intensity'] = input("¿Qué intensidad de detección de versiones deseas (1-9)? (Por defecto: 5): ") or '5'
        options['timeout'] = input("¿Quieres establecer un límite de tiempo para el host? (Ejemplo: 60s o 5m): ")
        options['scan_speed'] = input("Elige la velocidad del escaneo (1-lento, 5-rápido): ") or '4'

        scan_tcp_ports(ip, options)

    elif scan_type == 's':
        scan_nse_scripts(ip)

    else:
        print("Tipo de escaneo no válido. Elige 'b' para básico, 'a' para avanzado o 's' para scripts NSE.")
        
        

if __name__ == "__main__":
    main()
