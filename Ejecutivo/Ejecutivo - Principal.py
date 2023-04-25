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

def define_redes(fecha_inicial,final_date,tabla):
    query_redes_actual = f"""SELECT DISTINCT segmento,severity,nombre_red
    FROM {tabla} WHERE fecha_escaneo BETWEEN '01/{fecha_inicial}' AND '01/{final_date}'
    AND severity IN ('Alta','Critica') and upper(nombre_Red) = 'CGR';"""
    cur.execute(query_redes_actual)
    result_query_redes_actual = cur.fetchall()
    return result_query_redes_actual

############ Esta función define los parámetro de las fechas ############
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
        mes_pasado = '01'+'/0'+str(int(separa_fecha[0])-1)+'/'+str(separa_fecha[1])
        year_published = int(separa_fecha[1])-1
        date_published = '12'+'/'+str(year_published)
        next_month = int(separa_fecha[0]) + 1
        final_date = '0'+str(next_month) + '/'+separa_fecha[1]
        fecha_escaneo_valor = '15'+'/'+str(fecha_inicial)
    elif separa_fecha[0] == '03':
        actual_year = '01'+'/'+'01'+'/'+str(separa_fecha[1])
        mes_pasado = '01'+'/0'+str(int(separa_fecha[0])-1)+'/'+str(separa_fecha[1])
        year_published = int(separa_fecha[1])
        date_published = '01'+'/0'+str(year_published)
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

def fixed_flow(tabla,segmento,empresa,fecha_inicial,final_date,mes_pasado,severity):

    lista = []
    
    query_mes_actual = f"""select distinct concat(hostname, plugin_id, puerto, protocol)
    from {tabla} WHERE nombre_red = '{empresa}' and segmento = '{segmento}' 
    AND fecha_escaneo BETWEEN '01/{fecha_inicial}' AND '01/{final_date}'
    and severity = '{severity}';"""
    cur.execute(query_mes_actual)
    result_actual = cur.fetchall()
    #print(query_mes_actual)
    
    query_mes_pasado = f"""select distinct concat(hostname, plugin_id, puerto, protocol)
    from {tabla} WHERE nombre_red = '{empresa}' and segmento = '{segmento}' 
    AND fecha_escaneo BETWEEN '{mes_pasado}' AND '01/{fecha_inicial}'
    and severity = '{severity}';"""
    cur.execute(query_mes_pasado)   
    result_pasado = cur.fetchall()
    #print(query_mes_pasado)

    acdg = len(result_pasado)
    x = len([i for i in result_actual if i in result_pasado]) # Pending Flow
    pending_flow = x
    fixed_flow = acdg - pending_flow
    lista.append(fixed_flow)

    print("Cantidad fixed flow: {}".format(fixed_flow))
    
    return lista

def cant_vuln(tabla,segmento,fecha_inicial,final_date,empresa,severity):
    
    querycantidadvuln = f"""SELECT count(*)
    FROM {tabla} where nombre_red = '{empresa}' and segmento = '{segmento}' and fecha_escaneo BETWEEN '01/{fecha_inicial}' 
    AND '01/{final_date}' and severity = '{severity}';"""
    cur.execute(querycantidadvuln)
    cantidad_vuln = cur.fetchone()
    print('Cantidad de Vulnerabilidades: ', cantidad_vuln[0])
    return (cantidad_vuln)

def so_obsoletos(tabla,segmento,fecha_inicial,final_date,empresa,severity):

    lista = []
        
    query_so_obsoletos = f"""select concat(lower(hostname), plugin_id, nombre_red, severity)
    from {tabla} 
    WHERE segmento = '{segmento}' AND fecha_escaneo BETWEEN '01/{fecha_inicial}' AND '01/{final_date}' 
    and nombre_red = '{empresa}' and severity = '{severity}'
    and plugin_id in (2765,2766,12443,12451,
				  12468,12493,12494,12508,
				  12511,14239,14611,15944,
				  16054,16211,18128,18313,
				  18389,19699,19832,20751,
				  21089,21626,21801,21828,
				  21849,21881,21882,21923,
				  22086,22135,22879,22918,
				  25479,25498,25908,25924,
				  26207,26906,29190,29203,
				  32139,32160,33850,35186,
				  35190,40795,40808,42360,
				  47709,48301,48312,55933,
				  65041,65062,65632,67070,
				  67413,67516,67540,67579,
				  67609,67678,67763,67917,
				  67955,68081,68772,68773,
				  69182,72582,73182,73531,
				  73598,74379,76644,77781,
				  77805,77806,80888,84729,
				  88001,88561,97996,100064,
				  103877,108797,111414,118715,
				  118716,122403,122614,122615,
				  123226,124117,127637,127976,
				  134863,134864,134865,134866,
				  136507,137754,801593,801594,
				  801602,801604,801608,801609,
				  802018,144951,144952,137754);"""
    cur.execute(query_so_obsoletos)
    result_so_obsoletos = cur.fetchall()
    
    so_obsoletos = len(result_so_obsoletos)

    lista.append(so_obsoletos)

    print("Cantidad Cantidad SO Obsoletos: {}".format(so_obsoletos))

    return lista

def equipos_escaneos(segmento,fecha_inicial,final_date,tabla,empresa):

    query_cantidad = """SELECT activo_ponderado,cantidad_host FROM kpi WHERE fecha_escaneo 
	BETWEEN '01/{}' AND '01/{}' 
    AND nombre_red = '{}' 
    and segmento = '{}' 
    and idescaneo = '6';""".format(fecha_inicial, final_date, empresa, segmento)
    cur.execute(query_cantidad)
    cantidad_numero = cur.fetchone()

    if(cantidad_numero == None):
        equipos_escaneados = 0
    else:
        equipos_escaneados = cantidad_numero[0]
    
    inventario_total = cantidad_numero[1]
    
    lista = []
    lista.append(equipos_escaneados)
    lista.append(inventario_total)
    print("Cantidad Equipos Escaneados: {}".format(equipos_escaneados))
    print("Inventario total: {}".format(inventario_total))

    return lista


def main():
 
    ############# seteo de fechas necesarias para las querys #############
    fechas = datos_fecha()
    fecha_inicial = fechas[0]
    final_date = fechas[1]
    date_published = fechas[2]
    fecha_escaneo_valor = fechas[3]
    mes_pasado = fechas[4]
    actual_year = fechas[5]

    print(f'Fecha inicial: {fecha_inicial}')
    print(f'Fecha final: {final_date}')
    print(f'Mes pasado: {mes_pasado}')
    print(f'Año actual: {actual_year}')

    

    ############# aquí se configuran los valores de tabla a consultar y el idescaneo #############
    tabla = 'vuln_excellia'
    idescaneo = 7

    redes = define_redes(fecha_inicial,final_date,tabla)

    ############# Aquí se comienzan a ejecutar las funciones #############       
    for red in redes:
        #valor_segmento = inventory_dictionary[empresa]
        print('Empresa: ', red[2], ' Segmento: ', red[0], ' Severidad: ', red[1])
        try:
            # fecha = red[1]
            A = fixed_flow(tabla,red[0],red[2],fecha_inicial,final_date,mes_pasado,red[1])
            D = equipos_escaneos( red[0],fecha_inicial,final_date,tabla,red[2])
            B = cant_vuln(tabla,red[0],fecha_inicial,final_date,red[2],red[1])
            C = so_obsoletos(tabla,red[0],fecha_inicial,final_date,red[2],red[1])
            
            query_insert = f"""INSERT INTO vuln_excellia_ejecutivo
            (fecha_escaneo, empresa, segmento, severity, cant_vulns, 
            cant_obsoletos, cant_remediadas, equipos_escaneados,inventario_total)
            VALUES 
            ('01/{fecha_inicial}','{red[2]}','{red[0]}','{red[1]}',{B[0]},{C[0]},{A[0]},{D[0]},{D[1]});"""
            print(query_insert)
            cur.execute(query_insert)
            conexion.commit()
        except (TypeError) as e:
            print("Error - Data no cargada " + red[0])
            pass

if __name__ == '__main__':
    main()