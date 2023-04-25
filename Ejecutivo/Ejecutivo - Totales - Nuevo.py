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
	and severity = '{severity}' and empresa NOT IN ('Ransa Total', 'Primax Total')
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
	and severity = '{severity}' and empresa NOT IN ('Ransa Total', 'Primax Total')
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
	and severity = '{severity}' and empresa NOT IN ('Ransa Total', 'Primax Total')
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
	and severity = '{severity}' and empresa NOT IN ('Ransa Total', 'Primax Total')
	;"""
    cur.execute(query_equipos_escaneados)
    result_equipos_escaneados = cur.fetchone()

    equipos_escaneados = result_equipos_escaneados[0]
    lista.append(equipos_escaneados)
    print("Cantidad Cantidad Vulnerabilidades: {}".format(equipos_escaneados))

    return lista

def define_redes(fecha_inicial,final_date,tabla):
    query_redes_actual = f"""SELECT DISTINCT segmento,severity,nombre_red
    FROM {tabla} WHERE fecha_escaneo BETWEEN '01/{fecha_inicial}' AND '01/{final_date}'
    AND severity IN ('Alta','Critica');"""
    cur.execute(query_redes_actual)
    result_query_redes_actual = cur.fetchall()
    return result_query_redes_actual


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
    redes = define_redes(fecha_inicial,final_date,tabla)
    for red in redes:
        print('Empresa: ', red[2], ' Segmento: ', red[0])
        try:
            A = cant_vuln(tabla,red[0],fecha_inicial,final_date,severity)
            B = cant_obsoletos(tabla,red[0],fecha_inicial,final_date,severity)
            C = cant_remediadas(tabla,red[0],fecha_inicial,final_date,severity)
            D = equipos_escaneados(tabla,red[0],fecha_inicial,final_date,severity)

            query_fecha = """SELECT DISTINCT fecha_escaneo FROM {} 
            WHERE fecha_escaneo BETWEEN '01/{}' AND '01/{}' 
	    	AND severity = '{}' 
	    	AND segmento = '{}'
	    	;;""".format(tabla,fecha_inicial,final_date,severity,red[0])
            cur.execute(query_fecha)
            result_query_fecha = cur.fetchone()
            fecha = result_query_fecha[0]

            print("FECHA ESCANEO - {}".format(fecha))

            query_insert = f"""INSERT INTO vuln_excellia_ejecutivo
            (fecha_escaneo, empresa, segmento, severity, cant_vulns, 
            cant_obsoletos, cant_remediadas, equipos_escaneados)
            VALUES 
            ('{fecha}','Excellia - Total','{red[0]}','{severity}',{A[0]},{B[0]},{C[0]},{D[0]});"""
            cur.execute(query_insert)
            conexion.commit()
        except (TypeError) as e:
            print("Error - Data no cargada ")
            pass

