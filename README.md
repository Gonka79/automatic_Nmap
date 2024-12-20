# AUTO-NMAP: Automated Nmap Port Scanning Script

This Python script automates the process of Nmap port scanning, providing options for basic, advanced, and NSE script-based scans. It includes features such as scanning only active hosts (ignoring those that are down) and displaying a notification of how many ports will be scanned.

## Features
- **Basic scan**: Scans the top 1000 most important ports.
- **Advanced scan**: Scans all TCP and/or UDP ports (1-65535 for TCP, top 1000 for UDP).
- **NSE script scan**: Allows the user to select specific Nmap Scripting Engine (NSE) scripts to apply.
- **Active hosts only**: Displays results only for hosts that are up.
- **Port count notification**: Displays the number of ports being scanned before the scan starts.
- **Export results**: Option to export scan results in `TXT`, `XML`, or `JSON` format.
- **Graphical User Interface (GUI)**: Optional interface using Tkinter (coming soon).

## Installation

### Requirements
- **Python 3.x**
- **Nmap** installed on your system
- **python-nmap** library for Python

### Quick Installation
You can install all required dependencies using the provided script:

1. Run the installation script:
    ```bash
    git clone https://github.com/Gonka79/automatic_Nmap.git
    cd automatic_Nmap
    sudo ./install_resources.sh
    ```

This script installs Nmap, Python, and the necessary Python packages in a virtual environment.

### Manual Installation

1. **Create a virtual environment**:
    ```bash
    python3 -m venv venv
    ```

2. **Activate the virtual environment**:
    ```bash
    source venv/bin/activate
    ```

3. **Install the `python-nmap` package using `pip`**:
    ```bash
    pip install python-nmap --break-system-packages
    ```

4. (Optional) **Deactivate the virtual environment**:
    ```bash
    deactivate
    ```

### Running the Script

1. Ensure you have **Nmap** installed:
    ```bash
    sudo apt-get install nmap
    ```

2. Run the Python script:
    ```bash
    sudo python3 auto_nmap.py
    ```

Follow the prompts to enter the IP addresses or ranges, and select the type of scan (basic, advanced, or NSE script-based).

## Usage Example

- To scan a specific IP range, enter it like this:
    ```
    192.168.1.100-150
    ```

- For a basic scan, select "b".
- For advanced options like full port scanning or service detection, select "a".
- For NSE script scanning, select "s".

## Exporting Results
The script includes an option to export scan results. After completing the scan, you will be prompted to choose an export format:
- **TXT**: Exports results in plain text format.
- **XML**: Exports results in XML format.
- **JSON**: Exports results in JSON format.

You will also be asked to provide a filename for the exported results.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ESPAÑOL 
# AUTO-NMAP: Script Automatizado de Escaneo de Puertos con Nmap

Este script en Python automatiza el proceso de escaneo de puertos utilizando Nmap, proporcionando opciones para escaneos básicos, avanzados y basados en scripts NSE. Incluye características como el escaneo solo de hosts activos (ignorando los que están caídos) y la notificación de cuántos puertos serán escaneados.

## Características
- **Escaneo básico**: Escanea los 1000 puertos más importantes.
- **Escaneo avanzado**: Escanea todos los puertos TCP y/o UDP (puertos 1-65535 para TCP, los 1000 principales para UDP).
- **Escaneo con scripts NSE**: Permite al usuario seleccionar scripts específicos de Nmap (NSE).
- **Solo hosts activos**: Muestra resultados solo de hosts que están activos (up).
- **Notificación de puertos**: Muestra la cantidad de puertos que se escanearán antes de iniciar el escaneo.
- **Exportar resultados**: Opción para exportar resultados del escaneo en formato `TXT`, `XML` o `JSON`.
- **Interfaz gráfica (GUI)**: Interfaz opcional usando Tkinter (próximamente).

## Instalación

### Requisitos
- **Python 3.x**
- **Nmap** instalado en tu sistema
- Librería **python-nmap** para Python

### Instalación rápida
Puedes instalar todas las dependencias necesarias usando el siguiente script:

1. Ejecuta el script de instalación:
    ```bash
    git clone https://github.com/Gonka79/automatic_Nmap.git
    cd automatic_Nmap
    sudo ./install_resources.sh
    ```

Este script instala Nmap, Python y los paquetes de Python necesarios en un entorno virtual.

### Instalación manual

1. **Crea un entorno virtual**:
    ```bash
    python3 -m venv venv
    ```

2. **Activa el entorno virtual**:
    ```bash
    source venv/bin/activate
    ```

3. **Instala el paquete `python-nmap` usando `pip`**:
    ```bash
    pip install python-nmap --break-system-packages
    ```

4. (Opcional) **Desactiva el entorno virtual**:
    ```bash
    deactivate
    ```

### Ejecución del Script

1. Asegúrate de tener **Nmap** instalado:
    ```bash
    sudo apt-get install nmap
    ```

2. Ejecuta el script de Python:
    ```bash
    sudo python3 auto_nmap.py
    ```

Sigue las indicaciones para introducir las direcciones IP o rangos, y selecciona el tipo de escaneo (básico, avanzado o basado en scripts NSE).

## Ejemplo de Uso

- Para escanear un rango de IP específico, introdúcelo de la siguiente manera:
    ```
    192.168.1.100-150
    ```

- Para un escaneo básico, selecciona "b".
- Para opciones avanzadas como escaneo completo de puertos o detección de servicios, selecciona "a".
- Para escaneo con scripts NSE, selecciona "s".

## Exportar Resultados
El script incluye una opción para exportar los resultados del escaneo. Después de completar el escaneo, podrás elegir el formato de exportación:
- **TXT**: Exporta resultados en formato de texto plano.
- **XML**: Exporta resultados en formato XML.
- **JSON**: Exporta resultados en formato JSON.

También se te pedirá que indiques un nombre para el archivo exportado.

## Licencia
Este proyecto está bajo la licencia MIT - consulta el archivo [LICENSE](LICENSE) para más detalles.

