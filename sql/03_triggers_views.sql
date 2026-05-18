CREATE OR REPLACE FUNCTION avg_response_time(p_operator_id INT) RETURNS NUMERIC AS $$
DECLARE
    avg_minutes NUMERIC;
BEGIN
    SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/60), 0)
    INTO avg_minutes FROM public.incidents
    WHERE operator_id = p_operator_id AND status = 'Closed';
    RETURN ROUND(avg_minutes, 2);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION check_threat_level(p_incident_id INT) RETURNS BOOLEAN AS $$
DECLARE
    t_level INT;
BEGIN
    SELECT threat_level INTO t_level FROM public.incidents WHERE incident_id = p_incident_id;
    RETURN (t_level >= 1 AND t_level <= 5);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION count_incidents_period(start_date TIMESTAMP, end_date TIMESTAMP) RETURNS INT AS $$
DECLARE
    total_count INT;
BEGIN
    SELECT COUNT(*) INTO total_count FROM public.incidents WHERE created_at BETWEEN start_date AND end_date;
    RETURN total_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION top_vulnerabilities() RETURNS TABLE(rule_name VARCHAR, usage_count BIGINT) AS $$
BEGIN
    RETURN QUERY
    SELECT sr.rule_name::VARCHAR, COUNT(rv.violation_id) AS usage_count
    FROM public.security_rules sr
    JOIN public.rule_violations rv ON sr.rule_id = rv.rule_id
    GROUP BY sr.rule_name
    ORDER BY usage_count DESC;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION log_incident_changes() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.incident_log (incident_id, action_type, new_status) 
        VALUES (NEW.incident_id, 'INSERT', NEW.status);
    ELSIF TG_OP = 'UPDATE' THEN
        IF OLD.status IS DISTINCT FROM NEW.status THEN
            INSERT INTO public.incident_log (incident_id, action_type, old_status, new_status) 
            VALUES (NEW.incident_id, 'UPDATE', OLD.status, NEW.status);
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION enforce_threat_level() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.threat_level < 1 OR NEW.threat_level > 5 OR NEW.threat_level IS NULL THEN
        NEW.threat_level := 3;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION prevent_open_incident_delete() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status != 'Closed' THEN
        RAISE EXCEPTION 'Нельзя удалить инцидент, пока он не закрыт!';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_last_modified() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION escalate_critical_rule() RETURNS TRIGGER AS $$
DECLARE
    rule_thresh DECIMAL;
BEGIN
    SELECT threshold INTO rule_thresh FROM public.security_rules WHERE rule_id = NEW.rule_id;
    IF rule_thresh = 0 THEN
        UPDATE public.incidents SET threat_level = 5 WHERE tx_id = NEW.tx_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_incident_audit ON public.incidents;
DROP TRIGGER IF EXISTS trg_check_threat ON public.incidents;
DROP TRIGGER IF EXISTS trg_prevent_delete ON public.incidents;
DROP TRIGGER IF EXISTS trg_last_modified ON public.incidents;
DROP TRIGGER IF EXISTS trg_escalate_critical ON public.rule_violations;

CREATE TRIGGER trg_incident_audit AFTER INSERT OR UPDATE ON public.incidents FOR EACH ROW EXECUTE FUNCTION log_incident_changes();
CREATE TRIGGER trg_check_threat BEFORE INSERT OR UPDATE ON public.incidents FOR EACH ROW EXECUTE FUNCTION enforce_threat_level();
CREATE TRIGGER trg_prevent_delete BEFORE DELETE ON public.incidents FOR EACH ROW EXECUTE FUNCTION prevent_open_incident_delete();
CREATE TRIGGER trg_last_modified BEFORE UPDATE ON public.incidents FOR EACH ROW EXECUTE FUNCTION update_last_modified();
CREATE TRIGGER trg_escalate_critical AFTER INSERT ON public.rule_violations FOR EACH ROW EXECUTE FUNCTION escalate_critical_rule();