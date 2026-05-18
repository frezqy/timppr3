TRUNCATE TABLE public.clients, public.operators, public.transactions, public.security_rules, public.rule_violations, public.incidents, public.blacklist, public.vulnerabilities, public.incident_vulnerabilities, public.incident_log RESTART IDENTITY CASCADE;

INSERT INTO public.clients (client_id, last_name, first_name, patronymic, email, phone) VALUES
(1, 'Иванов', 'Иван', 'Иванович', 'ivanov@email.com', '+79991112233'),
(2, 'Петров', 'Петр', 'Петрович', 'petrov@email.com', '+79992223344');

INSERT INTO public.operators (operator_id, last_name, first_name, patronymic, position) VALUES
(1, 'Сидоров', 'Алексей', 'Николаевич', 'Старший аналитик'),
(2, 'Кузнецова', 'Елена', 'Сергеевна', 'Младший оператор');

INSERT INTO public.transactions (tx_id, client_id, amount, ip_address, status) VALUES
(1, 1, 15000.00, '192.168.1.50', 'Approved'),
(2, 2, 95000.00, '45.12.89.23', 'Under_Review');

INSERT INTO public.security_rules (rule_id, rule_name, description, threshold) VALUES
(1, 'Лимит суммы', 'Проверка транзакций, превышающих 50000 рублей', 50000.00),
(2, 'Подозрительный IP', 'Проверка вхождения IP адреса в списки брутфорса', 0.00);

INSERT INTO public.rule_violations (violation_id, tx_id, rule_id) VALUES
(1, 2, 1);

INSERT INTO public.incidents (incident_id, tx_id, operator_id, threat_level, status) VALUES
(1, 2, 1, 3, 'Open');

INSERT INTO public.blacklist (blacklist_id, operator_id, entity_type, entity_value) VALUES
(1, 1, 'IP', '45.12.89.23');

INSERT INTO public.vulnerabilities (vulnerability_id, vulnerability_name, cve_id, severity) VALUES
(1, 'SQL Injection', 'CVE-2026-1234', 'High'),
(2, 'XSS Vulnerability', 'CVE-2026-5678', 'Medium');

INSERT INTO public.incident_vulnerabilities (incident_id, vulnerability_id) VALUES
(1, 1);