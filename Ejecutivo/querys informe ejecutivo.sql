---------------- HOST VIVOS ----------------
select nombre_Red, sum(cantidad_host) "inventario_total", sum(activo_ponderado) "escaneados" from (
select distinct nombre_Red, segmento, cantidad_host, activo_ponderado
from kpi
where idescaneo = 6
	and((fecha_escaneo between '01/02/2023' and '01/03/2023' and segmento = 'Servidores')
	or (fecha_escaneo between '01/03/2023' and '01/04/2023' and segmento in ('Estaciones de Trabajo','Equipos de Comunicación')))
	) as a
group by nombre_Red;

---------------- VULNS CRITICAS Y ALTAS ----------------
select empresa, severity, sum(cant_vulns) from ( 
select * 
from vuln_Excellia_ejecutivo
where ((fecha_escaneo between '01/02/2023' and '01/03/2023' and segmento = 'Servidores')
	or (fecha_escaneo between '01/03/2023' and '01/04/2023' and segmento in ('Estaciones de Trabajo','Equipos de Comunicación')))
	) as a
group by empresa, severity;

---------------- VULNS REMED Y PEND ----------------
select nombre_red, count(*)
from vuln_Excellia
where ((fecha_escaneo between '01/02/2023' and '01/03/2023' and segmento = 'Servidores')
	or (fecha_escaneo between '01/03/2023' and '01/04/2023' and segmento in ('Estaciones de Trabajo','Equipos de Comunicación')))
and severity <> 'Info'
and upper(vulnerability_State) = 'FIXED'
--and upper(vulnerability_State) <> 'FIXED'
group by nombre_red;

---------------- OBSOLESCENCIA ----------------
select empresa, sum(soobsolete) "soobsolete", sum(softwareobsolete) "softwareobsolete"
from vuln_importantes where idescaneo = 7
and ((fecha_escaneo between '01/02/2023' and '01/03/2023' and segmento = 'Servidores')
	or (fecha_escaneo between '01/03/2023' and '01/04/2023' and segmento in ('Estaciones de Trabajo','Equipos de Comunicación')))
group by empresa;

---------------- TOP 10 CRITICAS ----------------
select * from (	
select nombre_Red, title, count(*), exploit,
		row_number() over (partition by nombre_red order by count(*) desc) as row
from vuln_Excellia
where ((fecha_escaneo between '01/02/2023' and '01/03/2023' and segmento = 'Servidores')
	or (fecha_escaneo between '01/03/2023' and '01/04/2023' and segmento in ('Estaciones de Trabajo','Equipos de Comunicación')))
and upper(severity) = 'CRITICA'
and upper(nombre_Red) not like '%TOTAL%' and upper(nombre_Red) not like '%RTRADING%'
--and upper(title) like '%MICROSOFT INTERNET EXPLORER UNSUPPORTED VERSION DETECTION%'
group by nombre_Red,title,exploit
) as a where row <= 10;

---------------- ANTIGUEDAD DE VULNS ----------------
select nombre_red,count(*)
from vuln_Excellia
where ((fecha_escaneo between '01/02/2023' and '01/03/2023' and segmento = 'Servidores')
	or (fecha_escaneo between '01/03/2023' and '01/04/2023' and segmento in ('Estaciones de Trabajo','Equipos de Comunicación')))
and severity <> 'Info'
--and current_Date-first_seen < 30
--and current_Date-first_seen between 30 and 90
and current_Date-first_seen > 90
group by nombre_red;