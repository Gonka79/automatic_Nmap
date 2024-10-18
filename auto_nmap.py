import nmap
import os

def scan_basic(ip, options):
    nm = nmap.PortScanner()
    
    if options.get('ping_scan'):
        scan_arguments = '-sn -vv'  # Solo ping scan
        print(f"Iniciando ping scan en {ip}...")
        nm.scan(ip, arguments=scan_arguments.strip())

        # Solo mostrar los hosts activos (detectados)
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                print(f"Host detectado: {host} ({nm[host].hostname()})")

    else:
        # Notificar la cantidad de puertos que se escanearán
        print("Se escanearán los 1000 puertos más importantes.")
        scan_arguments = '--top-ports 1000 -vv'  # Escaneo básico con verbose máximo y los 1000 puertos más importantes
        if options.get('os_detection'):
            scan_arguments += ' -O'  # Detección del sistema operativo
        
        if options.get('service_version'):
            scan_arguments += ' -sV'  # Detección de versiones de servicios (para TCP)

        print(f"Iniciando escaneo básico en {ip}...")
        nm.scan(ip, arguments=scan_arguments.strip())

        # Solo mostrar los hosts activos (up)
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

def scan_tcp_ports(ip, options):
    nm = nmap.PortScanner()
    
    # Notificar la cantidad de puertos que se escanearán
    print("Se escanearán todos los puertos TCP (1-65535).")
    scan_arguments = '-p 1-65535 -sS -T4 -vv'  # Escaneo avanzado TCP de todos los puertos
    
    # Añadimos opciones avanzadas según lo que el usuario elija
    if options.get('service_version'):
        scan_arguments += ' -sV'  # Detección de versiones de servicios
    
    if options.get('os_detection'):
        scan_arguments += ' -O'  # Detección del sistema operativo
    
    if options.get('traceroute'):
        scan_arguments += ' --traceroute'  # Hacer un traceroute al host
    
    if options.get('version_intensity'):
        scan_arguments += f" --version-intensity {options['version_intensity']}"  # Intensidad de la detección de versiones

    if options.get('timeout'):
        scan_arguments += f" --host-timeout {options['timeout']}"  # Limitar el tiempo de espera del host
    
    if options.get('scan_speed'):
        scan_arguments += f" -T{options['scan_speed']}"  # Ajuste de velocidad del escaneo

    print(f"Iniciando escaneo TCP avanzado en {ip} (puertos 1-65535)...")
    nm.scan(ip, arguments=scan_arguments.strip())

    # Solo mostrar los hosts activos (up)
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

def scan_udp_ports(ip):
    nm = nmap.PortScanner()
    
    # Notificar la cantidad de puertos que se escanearán
    print("Se escanearán los 1000 puertos UDP más importantes.")
    scan_arguments = '--top-ports 1000 -sU -T4 --max-retries 1 -vv'  # Escaneo UDP avanzado de los 1000 puertos más comunes
    
    print(f"Iniciando escaneo UDP en {ip} (1,000 puertos más comunes)...")
    nm.scan(ip, arguments=scan_arguments.strip())

    # Solo mostrar los hosts activos (up)
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            print(f"\nHost: {host} ({nm[host].hostname()})")

            for proto in nm[host].all_protocols():
                print(f"\nProtocolo: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    print(f"Puerto: {port}\tEstado: {nm[host][proto][port]['state']}")

def scan_nse_scripts(ip):
    nm = nmap.PortScanner()
    
    # Notificar la cantidad de puertos que se escanearán
    print("Se escanearán todos los puertos TCP (1-65535) con scripts NSE seleccionados.")
    scan_arguments = '-p 1-65535 -vv'  # Escaneo avanzado dirigido a scripts NSE

    # Scripts NSE específicos
    nse_scripts = []
    if input("¿Quieres ejecutar el script NSE 'http-enum'? (s/n): ").lower() == 's':
        nse_scripts.append('http-enum')
    
    if input("¿Quieres ejecutar el script NSE 'smb-os-discovery'? (s/n): ").lower() == 's':
        nse_scripts.append('smb-os-discovery')
    
    if input("¿Quieres ejecutar el script NSE 'ftp-anon'? (s/n): ").lower() == 's':
        nse_scripts.append('ftp-anon')

    if nse_scripts:
        scan_arguments += f" --script={','.join(nse_scripts)}"
    
    print(f"Iniciando escaneo avanzado dirigido a scripts NSE en {ip}...")
    nm.scan(ip, arguments=scan_arguments.strip())

    # Solo mostrar los hosts activos (up)
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

def main():
    # Preguntamos por la IP o el rango de IPs
    ip = input("Introduce la IP o el rango de IPs a escanear (Ejemplos: 192.168.1.1, 192.168.0.100-150, 192.168.1.0/24): ")

    # Preguntamos por el tipo de escaneo
    scan_type = input("¿Qué tipo de escaneo quieres? (b para básico / a para avanzado / s para scripts NSE): ").lower()

    # Validamos la entrada del tipo de escaneo
    if scan_type == 'b':
        # Opciones adicionales para el escaneo básico
        options = {}
        options['ping_scan'] = input("¿Quieres hacer solo un ping scan (sin escanear puertos)? (s/n): ").lower() == 's'

        if not options['ping_scan']:
            options['os_detection'] = input("¿Quieres intentar detectar el sistema operativo? (s/n): ").lower() == 's'
            options['service_version'] = input("¿Quieres detectar la versión de los servicios TCP? (s/n): ").lower() == 's'

        # Ejecutamos el escaneo básico
        scan_basic(ip, options)

    elif scan_type == 'a':
        # Opciones avanzadas para el escaneo TCP
        options = {}
        options['service_version'] = input("¿Quieres detectar la versión de los servicios TCP? (s/n): ").lower() == 's'
        options['os_detection'] = input("¿Quieres intentar detectar el sistema operativo? (s/n): ").lower() == 's'
        options['traceroute'] = input("¿Quieres hacer un traceroute al host? (s/n): ").lower() == 's'
        options['version_intensity'] = input("¿Qué intensidad de detección de versiones deseas (1-9)? (Por defecto: 5): ") or '5'
        options['timeout'] = input("¿Quieres establecer un límite de tiempo para el host? (Ejemplo: 60s o 5m): ")
        options['scan_speed'] = input("Elige la velocidad del escaneo (1-lento, 5-rápido): ") or '4'

        scan_tcp_ports(ip, options)

    elif scan_type == 's':
        # Escaneo con scripts NSE
        scan_nse_scripts(ip)

    else:
        print("Tipo de escaneo no válido. Elige 'b' para básico, 'a' para avanzado o 's' para scripts NSE.")

if __name__ == "__main__":
    main()
