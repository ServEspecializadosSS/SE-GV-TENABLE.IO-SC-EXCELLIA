SELECT fecha_escaneo, empresa, segmento, severity, cant_vulns, cant_obsoletos, cant_remediadas, equipos_escaneados
	FROM public.vuln_excellia_ejecutivo
	where empresa = 'Primax Total'
	order by fecha_escaneo
	;