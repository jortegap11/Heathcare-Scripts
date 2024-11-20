#!/usr/bin/python
"""
#    OBETIVO: Tratar un fichero de log de tráfico, para identificar cada flujo que lo atraviesa.
#  ESCENARIO: Traffic log de FortiGate o FortiAnalyzer
# REQUISITOS: Librerias Python instaladas    
#  INPUT-REQ: Fichero con export del log de FortiGate o FortiAnalyzer por argumentos o introducirlo en el momento de la ejecucion.
#  INPUT-OPT: Puedes pasar el nombre de fichero del log al ejecutar el comando, o introducirlo en el momento de la ejecucion.
#     OUTPUT: Fichero excel con las reglas filtradas (filtrado_YYMMDD-HHMMSS_FicheroLogATratar.xlsx)
#  EJECUCION: py_fw_limpieza_any_v2.py <FicheroLogATratar.txt>
"""

__author__ = 'Santiago de Vega'
__email__ = "sdevega@kyndryl.com"
__title__ = 'Leer log Fortigate'
__version__ = '2.3'


"""
Historico versiones:
2.4 - Menu de arranque del script
2.3 - Eliminar dependencias de path y obliga a introducir fichero a analizar como argumento de entrada o user-prompt
2.2 - Si el puerto es UDP no descarta los bytes-recibidos=0
2.1 - Añadida lógica para cambiar origen/destino a ALL/ANY cuando proceda.
2.0 - Añadida lógica para agrupar orígenes, destinos y puertos y volcado en excel.
1.0 - Parseo de logs y volcado en CSV.
"""

from datetime import datetime
import pandas as pd
import csv
import re
import sys
import os

def openLogFile(log_filename):
  try:
    input_file = open(log_filename, "r")
    log = input_file.readlines()
    input_file.close()
    return log
  except:
    print('ERROR al abrir el fichero de log.')
    sys.exit(1)
  
def parseLog(log):
  """
  Parsea todo el log para ponerlo en formato estructurado
  """
  pattern = r'(^[^=]+|[^=]+)=(".+?"|[\d\.:-]+? )'
  log_list = []

  print("Tratando el fichero de log...")

  for log_line in log:
    log_dict = {}
    match_strings = re.findall(pattern, log_line)
    for group in match_strings:
      key = group[0].strip()
      value = group[1].strip().replace('"', '')
      log_dict[key] = value

    #Coprueba si el servicio es UDP, si no, revisa que exista puerto-destino y que la respuesta no sean 0 bytes
    #service="UDP_HIGH_PORTS"

    #Solo se añade si hay puerto-destino, y si existe respuesta que no sean 0 bytes
    if 'dstport' in log_dict and 'rcvdbyte' in log_dict:
      if log_dict['rcvdbyte'] != '0':
        log_list.append(log_dict)

  return log_list

def writeCSV(log_list, csv_filename):
  """
  Escribe los resultados en un CSV.
    log_list: son los datos que tiene que escribir en el fichero
    log_file_name: nombre del fichero de log que se está tratando
  """
  print("Generando fichero CSV intermedio...")
  #listofkeys = ['date', 'time', 'eventtime', 'policyid', 'policyname', 'srcintf', 'dstintf', 'srcip', 'dstip', 'dstport', 'service', 'action', 'sentbyte', 'rcvdbyte']
  listofkeys = ['srcintf', 'dstintf', 'srcip', 'dstip', 'service']
  with open(csv_filename, 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=listofkeys, delimiter=';', extrasaction='ignore')
    writer.writeheader()
    writer.writerows(log_list)
  file.close()

def filterCSV(csv_file_name):
  """
  Filtra el CSV para agrupar orígenes destinos y puertos. Genera un EXCEL final con formato.
  Devuelve DataFrame(df) con los datos filtrados
  """
  print("Filtrando el fichero de log...")
  df = pd.read_csv(csv_file_name, sep=';')

  #Agrupa por IP origen
  df.srcip.astype(str)
  df2 = df.groupby(['srcintf','dstintf','dstip','service'])['srcip'].apply(', '.join).reset_index()

  #Elimina duplicados en columna srcip
  df2['srcip']= df2['srcip'].str.split(', ').map(set).str.join(', ')

  #Agrupa por servicios
  df2.service.astype(str)
  df3 = df2.groupby(['srcintf','dstintf','srcip','dstip'])['service'].apply(', '.join).reset_index()

  #Agrupa por destinos
  df3.service.astype(str)
  df4 = df3.groupby(['srcintf','dstintf','srcip','service'])['dstip'].apply(', '.join).reset_index()

  #Si el destino/origen tiene más de 15 IP lo cambia por ALL/ANY
  #df4['dstip'].mask(df4['dstip'].str.count(',')>=15 ,'ANY', inplace=True)
  #df4['srcip'].mask(df4['srcip'].str.count(',')>=15 ,'ANY', inplace=True)

  #Renombra columnas
  df5 = df4.rename(columns={'srcintf':'SOURCE-INTERFACE',
                            'dstintf':'DESTINATION-INTERFACE',
                            'srcip':'SOURCE-IP',
                            'dstip':'DESTINATION-IP',
                            'service':'SERVICE-PORT'})
  #Inserta columnas
  df5.insert(0, 'NAME', 'LIMPIEZA_ANY_')
  df5.insert(6, 'AUTORIZACION-CYBER', '')
  df5.insert(7, 'COMENTARIOS', '')

  #Guarda los datos en un excel
  column_order = ['NAME','SOURCE-INTERFACE','DESTINATION-INTERFACE','SOURCE-IP','DESTINATION-IP','SERVICE-PORT','AUTORIZACION-CYBER','COMENTARIOS']
  print("Generando fichero EXCEL definitivo: " + csv_file_name + '.xlsx')
  df5.to_excel(csv_file_name + '.xlsx', columns=column_order)

  return df5


def main():
  print("****************************************************************")
  print("*** BIENVENIDO AL FORTI-PROGRAMA DE REVISIÓN DE LOGS ANY-ANY ***")
  print("****************************************************************")

  #Comprobacion de argumentos. Si no se pasa el nombre como argumento, se pide al usuario que lo introduzca.
  if len(sys.argv) == 2:
    print("El fichero de log a tratar es: " + sys.argv[1])
    log_file_name = sys.argv[1]
  else:
    log_file_name = input('Introduce el nombre del fichero de log a tratar: ')
    
  log_file = openLogFile(log_file_name)
  log_list = parseLog(log_file)
  
  #Obtiene fecha actual y genera nombre fichero CSV
  actualtime = datetime.now()
  formatedtime = actualtime.strftime('%Y%m%d-%H%M%S')
  csv_file_name = "filtrado_" + formatedtime + "_" + log_file_name + ".csv"
  #Escribe en CSV intermedio los datos tras el parseo del fichero log
  writeCSV(log_list,csv_file_name)
  #Genera el Excel final filtrado
  filterCSV(csv_file_name)
  #Elimina el fichero CSV intermedio
  print("Eliminando fichero CSV intermedio...")
  os.remove(csv_file_name)

  entrada = input('\nEjecucion finalizada. Pulsa INTRO para volver a empezar, o escribe SALIR para cerrar el programa: ')
  if entrada.upper() == 'SALIR':
    return 0
  else:
    main()


if __name__ == "__main__":
  main()