SELECT * FROM top_vulnerabilities();

INSERT INTO public.incidents (incident_id, tx_id, operator_id, status, threat_level) VALUES (2, 1, 1, 'Open', 99);

SELECT * FROM public.incident_log;

DELETE FROM public.incidents WHERE status = 'Open';

UPDATE public.clients SET email = MD5(email) WHERE client_id = 1;

SELECT last_name, first_name, email FROM public.clients WHERE client_id = 1;

UPDATE public.incidents SET status = 'Investigating', threat_level = 99 WHERE incident_id = 1;

SELECT incident_id, status, threat_level, updated_at FROM public.incidents WHERE incident_id = 1;

DELETE FROM public.incidents WHERE incident_id = 1;

UPDATE public.incidents SET status = 'Closed', updated_at = CURRENT_TIMESTAMP + INTERVAL '15 minutes' WHERE incident_id = 1;

SELECT avg_response_time(1) AS avg_time, check_threat_level(1) AS is_valid;