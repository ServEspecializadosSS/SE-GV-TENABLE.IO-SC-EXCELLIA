from email.policy import EmailPolicy
import psycopg2
import time
#from tqdm impuerto tqdm
#impuerto progressbar
#from getpass impuerto getpass

pg_user = "postgres"  # raw_input("Ingrese su usuario: ")
pg_password = "SecureSoft123$"  # getpass("Ingrese su contraseña: ")

# datos para la conexión
PG_HOST = "192.168.88.21"
PG_PORT = "5432"
PG_USER = pg_user
PG_PASS = pg_password
PG_BD = "vulndb"

try:
    conexion_str = 'host =%s port=%s user=%s password=%s dbname=%s' % (
        PG_HOST, PG_PORT, PG_USER, PG_PASS, PG_BD)
    conexion = psycopg2.connect(conexion_str)
    print("La conexión fue establecida")
except:
    print("La conexión fallo")
    print("Vuelve a intentar conectarte")
    time.sleep(2)
    exit()

cur = conexion.cursor()

def datos_fecha():
    fecha_inicial = input("Inserta el mes y el año (Ejm.01/2019) => ")
    separa_fecha = fecha_inicial.split('/')
    if separa_fecha[0] == '12':
        new_year = int(separa_fecha[1])+1
        actual_year = '01'+'/'+'01'+'/'+str(separa_fecha[1])
        mes_pasado = '01'+'/'+str(int(separa_fecha[0])-1)+'/'+str(separa_fecha[1])
        final_date = '01'+'/'+str(new_year)
        date_published = '10'+'/'+str(separa_fecha[1])
        fecha_escaneo_valor = '15'+'/'+str(fecha_inicial)
    elif separa_fecha[0] == '01':
        actual_year = '01'+'/'+'01'+'/'+str(separa_fecha[1])
        mes_pasado = '01'+'/'+'12'+'/'+str(int(separa_fecha[1])-1)
        year_published = int(separa_fecha[1])-1
        date_published = '11'+'/'+str(year_published)
        next_month = int(separa_fecha[0]) + 1
        final_date = '0'+str(next_month) + '/'+separa_fecha[1]
        fecha_escaneo_valor = '15'+'/'+str(fecha_inicial)
    elif separa_fecha[0] == '02':
        actual_year = '01'+'/'+'01'+'/'+str(separa_fecha[1])
        mes_pasado = '01'+'/'+str(int(separa_fecha[0])-1)+'/'+str(separa_fecha[1])
        year_published = int(separa_fecha[1])-1
        date_published = '12'+'/'+str(year_published)
        next_month = int(separa_fecha[0]) + 1
        final_date = '0'+str(next_month) + '/'+separa_fecha[1]
        fecha_escaneo_valor = '15'+'/'+str(fecha_inicial)
    elif separa_fecha[0] == '03':
        actual_year = '01'+'/'+'01'+'/'+str(separa_fecha[1])
        mes_pasado = '01'+'/'+str(int(separa_fecha[0])-1)+'/'+str(separa_fecha[1])
        year_published = int(separa_fecha[1])
        date_published = '01'+'/'+str(year_published)
        next_month = int(separa_fecha[0]) + 1
        final_date = '0'+str(next_month) + '/'+separa_fecha[1]
        fecha_escaneo_valor = '15'+'/'+str(fecha_inicial)
    else:
        actual_year = '01'+'/'+'01'+'/'+str(separa_fecha[1])
        mes_pasado = '01'+'/'+str(int(separa_fecha[0])-1)+'/'+str(separa_fecha[1])
        next_month = int(separa_fecha[0]) + 1
        final_date = '0'+str(next_month) + '/'+separa_fecha[1]

        month_published = int(separa_fecha[0])-2
        date_published = '0'+str(month_published)+'/'+str(separa_fecha[1])
        fecha_escaneo_valor = '15'+'/'+str(fecha_inicial)

    return fecha_inicial,final_date,date_published,fecha_escaneo_valor,mes_pasado,actual_year

def cant_vuln(tabla,segmento,fecha_inicial,final_date,severity):
    
    lista = []
    
    query_cant_vuln = f"""SELECT SUM(cant_vulns)
	FROM {tabla} where segmento = '{segmento}' and
	fecha_escaneo BETWEEN '01/{fecha_inicial}' AND '01/{final_date}'
	and severity = '{severity}' and empresa IN 
    ('Primax Ecuador','Primax Colombia','Primax Perú')
	;"""
    cur.execute(query_cant_vuln)
    result_cant_vuln = cur.fetchone()
    cant_vuln = result_cant_vuln[0]
    lista.append(cant_vuln)
    print("Cantidad Vulnerabilidades: {}".format(cant_vuln))

    return lista

def cant_obsoletos(tabla,segmento,fecha_inicial,final_date,severity):
    
    lista = []
    
    query_cant_obsoletos = f"""SELECT SUM(cant_obsoletos)
	FROM {tabla} where segmento = '{segmento}' and
	fecha_escaneo BETWEEN '01/{fecha_inicial}' AND '01/{final_date}'
	and severity = '{severity}' and empresa IN 
    ('Primax Ecuador','Primax Colombia','Primax Perú')
	;"""
    cur.execute(query_cant_obsoletos)
    result_cant_obsoletos = cur.fetchone()

    cant_obsoletos = result_cant_obsoletos[0]
    lista.append(cant_obsoletos)
    print("Cantidad Obsoletos: {}".format(cant_obsoletos))

    return lista

def cant_remediadas(tabla,segmento,fecha_inicial,final_date,severity):
    
    lista = []
    
    query_cant_remediadas = f"""SELECT SUM(cant_remediadas)
	FROM {tabla} where segmento = '{segmento}' and
	fecha_escaneo BETWEEN '01/{fecha_inicial}' AND '01/{final_date}'
	and severity = '{severity}' and empresa IN 
    ('Primax Ecuador','Primax Colombia','Primax Perú')
	;"""
    cur.execute(query_cant_remediadas)
    result_cant_remediadas = cur.fetchone()

    cant_remediadas = result_cant_remediadas[0]
    lista.append(cant_remediadas)
    print("Cantidad Remediadas: {}".format(cant_remediadas))

    return lista

def equipos_escaneados(tabla,segmento,fecha_inicial,final_date,severity):
    
    lista = []
    
    query_equipos_escaneados = f"""SELECT SUM(equipos_escaneados)
	FROM {tabla} where segmento = '{segmento}' and
	fecha_escaneo BETWEEN '01/{fecha_inicial}' AND '01/{final_date}'
	and severity = '{severity}' and empresa IN 
    ('Primax Ecuador','Primax Colombia','Primax Perú')
	;"""
    cur.execute(query_equipos_escaneados)
    result_equipos_escaneados = cur.fetchone()

    equipos_escaneados = result_equipos_escaneados[0]
    lista.append(equipos_escaneados)
    print("Cantidad Equipos Escaneados: {}".format(equipos_escaneados))

    return lista


if __name__ == '__main__':
 
    ############# seteo de fechas necesarias para las querys #############
    fechas = datos_fecha()
    fecha_inicial = fechas[0]
    final_date = fechas[1]

    print(f'Fecha inicial: {fecha_inicial}')
    print(f'Fecha final: {final_date}')

    ############# aquí se configuran los valores de tabla a consultar y el idescaneo #############
    tabla = 'vuln_excellia_ejecutivo'

    ############# Aquí se comienzan a ejecutar las funciones #############       
    try:
        A = cant_vuln(tabla,'Servidores',fecha_inicial,final_date,'Alta')
        B = cant_obsoletos(tabla,'Servidores',fecha_inicial,final_date,'Alta')
        C = cant_remediadas(tabla,'Servidores',fecha_inicial,final_date,'Alta')
        D = equipos_escaneados(tabla,'Servidores',fecha_inicial,final_date,'Alta')

        query_fecha = """SELECT DISTINCT fecha_escaneo FROM {} 
        WHERE fecha_escaneo BETWEEN '01/{}' AND '01/{}' 
		AND severity = 'Alta' 
		AND segmento = 'Servidores'
		;;""".format(tabla,fecha_inicial,final_date)
        cur.execute(query_fecha)
        result_query_fecha = cur.fetchone()
        fecha = result_query_fecha[0]
        
        print("SEGMENTO ALTAS LISTO - {}".format(fecha))

        query_insert = f"""INSERT INTO vuln_excellia_ejecutivo
        (fecha_escaneo, empresa, segmento, severity, cant_vulns, 
        cant_obsoletos, cant_remediadas, equipos_escaneados)
        VALUES 
        ('{fecha}','Primax Total','Servidores','Alta',{A[0]},{B[0]},{C[0]},{D[0]});"""
        cur.execute(query_insert)
        conexion.commit()

        A = cant_vuln(tabla,'Servidores',fecha_inicial,final_date,'Critica')
        B = cant_obsoletos(tabla,'Servidores',fecha_inicial,final_date,'Critica')
        C = cant_remediadas(tabla,'Servidores',fecha_inicial,final_date,'Critica')
        D = equipos_escaneados(tabla,'Servidores',fecha_inicial,final_date,'Critica')

        query_fecha = """SELECT DISTINCT fecha_escaneo FROM {} 
        WHERE fecha_escaneo BETWEEN '01/{}' AND '01/{}' 
		AND severity = 'Critica' 
		AND segmento = 'Servidores'
		;;""".format(tabla,fecha_inicial,final_date)
        cur.execute(query_fecha)
        result_query_fecha = cur.fetchone()
        fecha = result_query_fecha[0]
        
        print("SEGMENTO CRITICAS LISTO  - {}".format(fecha))

        query_insert = f"""INSERT INTO vuln_excellia_ejecutivo
        (fecha_escaneo, empresa, segmento, severity, cant_vulns, 
        cant_obsoletos, cant_remediadas, equipos_escaneados)
        VALUES 
        ('{fecha}','Primax Total','Servidores','Critica',{A[0]},{B[0]},{C[0]},{D[0]});"""
        cur.execute(query_insert)
        conexion.commit()

        print("--------------------------------- SERVIDORES  - {}".format(fecha))

        A = cant_vuln(tabla,'Estaciones de Trabajo',fecha_inicial,final_date,'Alta')
        B = cant_obsoletos(tabla,'Estaciones de Trabajo',fecha_inicial,final_date,'Alta')
        C = cant_remediadas(tabla,'Estaciones de Trabajo',fecha_inicial,final_date,'Alta')
        D = equipos_escaneados(tabla,'Estaciones de Trabajo',fecha_inicial,final_date,'Alta')

        query_fecha = """SELECT DISTINCT fecha_escaneo FROM {} 
        WHERE fecha_escaneo BETWEEN '01/{}' AND '01/{}' 
		AND severity = 'Alta' 
		AND segmento = 'Estaciones de Trabajo'
		;;""".format(tabla,fecha_inicial,final_date)
        cur.execute(query_fecha)
        result_query_fecha = cur.fetchone()
        fecha = result_query_fecha[0]
        
        print("FECHA ESCANEO - {}".format(fecha))

        query_insert = f"""INSERT INTO vuln_excellia_ejecutivo
        (fecha_escaneo, empresa, segmento, severity, cant_vulns, 
        cant_obsoletos, cant_remediadas, equipos_escaneados)
        VALUES 
        ('{fecha}','Primax Total','Estaciones de Trabajo','Alta',{A[0]},{B[0]},{C[0]},{D[0]});"""
        cur.execute(query_insert)
        conexion.commit()

        A = cant_vuln(tabla,'Estaciones de Trabajo',fecha_inicial,final_date,'Critica')
        B = cant_obsoletos(tabla,'Estaciones de Trabajo',fecha_inicial,final_date,'Critica')
        C = cant_remediadas(tabla,'Estaciones de Trabajo',fecha_inicial,final_date,'Critica')
        D = equipos_escaneados(tabla,'Estaciones de Trabajo',fecha_inicial,final_date,'Critica')

        query_fecha = """SELECT DISTINCT fecha_escaneo FROM {} 
        WHERE fecha_escaneo BETWEEN '01/{}' AND '01/{}' 
		AND severity = 'Critica' 
		AND segmento = 'Estaciones de Trabajo'
		;;""".format(tabla,fecha_inicial,final_date)
        cur.execute(query_fecha)
        result_query_fecha = cur.fetchone()
        fecha = result_query_fecha[0]
        
        print("FECHA ESCANEO - {}".format(fecha))

        query_insert = f"""INSERT INTO vuln_excellia_ejecutivo
        (fecha_escaneo, empresa, segmento, severity, cant_vulns, 
        cant_obsoletos, cant_remediadas, equipos_escaneados)
        VALUES 
        ('{fecha}','Primax Total','Estaciones de Trabajo','Critica',{A[0]},{B[0]},{C[0]},{D[0]});"""
        cur.execute(query_insert)
        conexion.commit()

        print("--------------------------------- ESTACIONES DE TRABAJO  - {}".format(fecha))

        A = cant_vuln(tabla,'Equipos de Comunicación',fecha_inicial,final_date,'Alta')
        B = cant_obsoletos(tabla,'Equipos de Comunicación',fecha_inicial,final_date,'Alta')
        C = cant_remediadas(tabla,'Equipos de Comunicación',fecha_inicial,final_date,'Alta')
        D = equipos_escaneados(tabla,'Equipos de Comunicación',fecha_inicial,final_date,'Alta')

        query_fecha = """SELECT DISTINCT fecha_escaneo FROM {} 
        WHERE fecha_escaneo BETWEEN '01/{}' AND '01/{}' 
		AND severity = 'Alta' 
		AND segmento = 'Equipos de Comunicación'
		;;""".format(tabla,fecha_inicial,final_date)
        cur.execute(query_fecha)
        result_query_fecha = cur.fetchone()
        fecha = result_query_fecha[0]
        
        print("FECHA ESCANEO - {}".format(fecha))

        query_insert = f"""INSERT INTO vuln_excellia_ejecutivo
        (fecha_escaneo, empresa, segmento, severity, cant_vulns, 
        cant_obsoletos, cant_remediadas, equipos_escaneados)
        VALUES 
        ('{fecha}','Primax Total','Equipos de Comunicación','Alta',{A[0]},{B[0]},{C[0]},{D[0]});"""
        cur.execute(query_insert)
        conexion.commit()
        
        A = cant_vuln(tabla,'Equipos de Comunicación',fecha_inicial,final_date,'Critica')
        B = cant_obsoletos(tabla,'Equipos de Comunicación',fecha_inicial,final_date,'Critica')
        C = cant_remediadas(tabla,'Equipos de Comunicación',fecha_inicial,final_date,'Critica')
        D = equipos_escaneados(tabla,'Equipos de Comunicación',fecha_inicial,final_date,'Critica')

        query_fecha = """SELECT DISTINCT fecha_escaneo FROM {} 
        WHERE fecha_escaneo BETWEEN '01/{}' AND '01/{}' 
		AND severity = 'Critica' 
		AND segmento = 'Equipos de Comunicación'
		;;""".format(tabla,fecha_inicial,final_date)
        cur.execute(query_fecha)
        result_query_fecha = cur.fetchone()
        fecha = result_query_fecha[0]
        
        print("FECHA ESCANEO - {}".format(fecha))

        query_insert = f"""INSERT INTO vuln_excellia_ejecutivo
        (fecha_escaneo, empresa, segmento, severity, cant_vulns, 
        cant_obsoletos, cant_remediadas, equipos_escaneados)
        VALUES 
        ('{fecha}','Primax Total','Equipos de Comunicación','Critica',{A[0]},{B[0]},{C[0]},{D[0]});"""
        cur.execute(query_insert)
        conexion.commit()

        print("--------------------------------- EQUIPOS DE COMUNICACIÓN  - {}".format(fecha))

    except (TypeError) as e:
        print("Error - Data no cargada ")
        pass

