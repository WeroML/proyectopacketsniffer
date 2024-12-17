#!/bin/bash

# Nombre del programa
PROGRAM_NAME="NetSpy"

# Rutas y archivos
SOURCE_FILE="packetsniffer.c"
OUTPUT_FILE="netspy"

# Mensajes de inicio
echo "----------------------------------------"
echo " Instalador para $PROGRAM_NAME"
echo "----------------------------------------"

# Verificar que el script se ejecute con privilegios de superusuario
if [ "$EUID" -ne 0 ]; then
  echo "Por favor, ejecuta este script como superusuario (sudo)."
  exit 1
fi

# Actualizar el sistema e instalar dependencias necesarias
echo "1. Actualizando el sistema e instalando dependencias..."
apt update
apt install libpcap-dev libncurses5-dev gcc

# Verificar que el archivo fuente existe
if [ ! -f "$SOURCE_FILE" ]; then
  echo "Error: No se encontró el archivo fuente $SOURCE_FILE en el directorio actual."
  exit 1
fi

# Compilar el programa
echo "2. Compilando el programa..."
gcc "$SOURCE_FILE" -o "$OUTPUT_FILE" -lpcap -lncurses -pthread
if [ $? -ne 0 ]; then
  echo "Error: Falló la compilación del programa."
  exit 1
fi

# Verificar dimensiones de la terminal
echo "3. Verificando las dimensiones de la terminal..."
COLUMNS=$(tput cols)
ROWS=$(tput lines)

if [ "$COLUMNS" -lt 140 ] || [ "$ROWS" -lt 40 ]; then
  echo "Advertencia: La terminal es demasiado pequeña. Recomendada: 140x40."
else
  echo "Dimensiones de terminal correctas."
fi

# Configuración final
echo "4. Configuración completada."
echo "El programa se ha compilado correctamente. Puedes ejecutarlo con:"
echo "sudo ./$OUTPUT_FILE"

# Finalización
echo "----------------------------------------"
echo " Instalación de $PROGRAM_NAME finalizada."
echo "----------------------------------------"
exit 0
