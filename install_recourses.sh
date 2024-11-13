#!/bin/bash

# Comprobación de privilegios
if [ "$EUID" -ne 0 ]; then
  echo "Por favor, ejecuta este script como root"
  exit
fi

# Preguntar si el sistema operativo es Kali o Parrot
read -p "¿Estás usando Kali Linux o Parrot OS? (s/n): " es_kali_parrot

# Función para instalar en entorno virtual
instalar_entorno_virtual() {
  echo "Instalando recursos en un entorno virtual..."
  python3 -m venv nmap_env
  source nmap_env/bin/activate
  pip install --upgrade pip
  pip install python-nmap --break-system-packages
  deactivate
  echo "Instalación completada en el entorno virtual 'nmap_env'"
}

# Función para instalación general
instalar_general() {
  echo "Instalando recursos de manera general..."
  pip install --upgrade pip
  pip install python-nmap
  echo "Instalación completada."
}

if [[ "$es_kali_parrot" == "s" || "$es_kali_parrot" == "S" ]]; then
  # Instalación para Kali o Parrot en entorno virtual
  instalar_entorno_virtual
else
  # Instalación para otros sistemas Linux
  read -p "¿Quieres instalar los recursos en un entorno virtual? (s/n): " instalar_virtual
  if [[ "$instalar_virtual" == "s" || "$instalar_virtual" == "S" ]]; then
    instalar_entorno_virtual
  else
    instalar_general
  fi
fi

# Confirmación de instalación para el usuario root
if [ "$EUID" -eq 0 ]; then
  echo "Ejecutando instalación para el usuario root..."
  instalar_general
fi

# Mensaje final
echo "Instalación completa. Ya puedes ejecutar Auto-Nmap usando: sudo python3 auto_nmap.py"
