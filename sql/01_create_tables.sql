DROP TABLE IF EXISTS public.incident_log CASCADE;
DROP TABLE IF EXISTS public.incident_vulnerabilities CASCADE;
DROP TABLE IF EXISTS public.vulnerabilities CASCADE;
DROP TABLE IF EXISTS public.blacklist CASCADE;
DROP TABLE IF EXISTS public.incidents CASCADE;
DROP TABLE IF EXISTS public.rule_violations CASCADE;
DROP TABLE IF EXISTS public.security_rules CASCADE;
DROP TABLE IF EXISTS public.transactions CASCADE;
DROP TABLE IF EXISTS public.operators CASCADE;
DROP TABLE IF EXISTS public.clients CASCADE;

CREATE TABLE public.clients (
    client_id SERIAL PRIMARY KEY,
    last_name VARCHAR(100) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    patronymic VARCHAR(100),
    email VARCHAR(150) NOT NULL UNIQUE,
    phone VARCHAR(20),
    reg_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE public.operators (
    operator_id SERIAL PRIMARY KEY,
    last_name VARCHAR(100) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    patronymic VARCHAR(100),
    position VARCHAR(100) NOT NULL
);

CREATE TABLE public.transactions (
    tx_id SERIAL PRIMARY KEY,
    client_id INT NOT NULL REFERENCES public.clients(client_id) ON DELETE CASCADE,
    amount DECIMAL(15,2) NOT NULL,
    tx_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NOT NULL,
    status VARCHAR(50) NOT NULL
);

CREATE TABLE public.security_rules (
    rule_id SERIAL PRIMARY KEY,
    rule_name VARCHAR(150) NOT NULL,
    description TEXT,
    threshold DECIMAL(15,2) NOT NULL
);

CREATE TABLE public.rule_violations (
    violation_id SERIAL PRIMARY KEY,
    tx_id INT NOT NULL REFERENCES public.transactions(tx_id) ON DELETE CASCADE,
    rule_id INT NOT NULL REFERENCES public.security_rules(rule_id) ON DELETE CASCADE,
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE public.incidents (
    incident_id SERIAL PRIMARY KEY,
    tx_id INT NOT NULL REFERENCES public.transactions(tx_id) ON DELETE CASCADE,
    operator_id INT NOT NULL REFERENCES public.operators(operator_id) ON DELETE RESTRICT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    threat_level INT NOT NULL,
    status VARCHAR(50) NOT NULL
);

CREATE TABLE public.blacklist (
    blacklist_id SERIAL PRIMARY KEY,
    operator_id INT NOT NULL REFERENCES public.operators(operator_id) ON DELETE RESTRICT,
    entity_type VARCHAR(50) NOT NULL,
    entity_value VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE public.vulnerabilities (
    vulnerability_id SERIAL PRIMARY KEY,
    vulnerability_name VARCHAR(150) NOT NULL,
    cve_id VARCHAR(50),
    severity VARCHAR(50) NOT NULL
);

CREATE TABLE public.incident_vulnerabilities (
    incident_id INT REFERENCES public.incidents(incident_id) ON DELETE CASCADE,
    vulnerability_id INT REFERENCES public.vulnerabilities(vulnerability_id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, vulnerability_id)
);

CREATE TABLE public.incident_log (
    log_id SERIAL PRIMARY KEY,
    incident_id INT NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    old_status VARCHAR(50),
    new_status VARCHAR(50),
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    changed_by VARCHAR(100) DEFAULT current_user
);