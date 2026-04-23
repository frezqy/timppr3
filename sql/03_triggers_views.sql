-- 1. функция подсчета среднего времени
create or replace function avg_response_time(p_operator_id int) returns numeric as $$
declare
    avg_minutes numeric;
begin
    select coalesce(avg(extract(epoch from (last_modified - created_at))/60), 0)
    into avg_minutes from incidents
    where operator_id = p_operator_id and status = 'closed';
    return round(avg_minutes, 2);
end;
$$ language plpgsql;

-- 2. функция проверки угрозы
create or replace function check_threat_level(p_incident_id int) returns boolean as $$
declare
    t_level int;
begin
    select threat_level into t_level from incidents where incident_id = p_incident_id;
    return (t_level >= 1 and t_level <= 5);
end;
$$ language plpgsql;

-- 3. функция подсчета инцидентов
create or replace function count_incidents_period(start_date timestamp, end_date timestamp) returns int as $$
declare
    total_count int;
begin
    select count(*) into total_count from incidents where created_at between start_date and end_date;
    return total_count;
end;
$$ language plpgsql;

-- 4. функция самых частых уязвимостей
create or replace function top_vulnerabilities() returns table(rule_name varchar, usage_count bigint) as $$
begin
    return query
    select sr.rule_name, count(rv.violation_id) as usage_count
    from security_rules sr
    join rule_violations rv on sr.rule_id = rv.rule_id
    group by sr.rule_name
    order by usage_count desc;
end;
$$ language plpgsql;

-- функции для 5 триггеров
create or replace function log_incident_changes() returns trigger as $$
begin
    if TG_OP = 'INSERT' then
        insert into incident_log (incident_id, action_type, new_status) values (NEW.incident_id, 'INSERT', NEW.status);
    elsif TG_OP = 'UPDATE' then
        if OLD.status is distinct from NEW.status then
            insert into incident_log (incident_id, action_type, old_status, new_status) values (NEW.incident_id, 'UPDATE', OLD.status, NEW.status);
        end if;
    end if;
    return NEW;
end;
$$ language plpgsql;

create or replace function enforce_threat_level() returns trigger as $$
begin
    if NEW.threat_level < 1 or NEW.threat_level > 5 or NEW.threat_level is null then
        NEW.threat_level := 3;
    end if;
    return NEW;
end;
$$ language plpgsql;

create or replace function prevent_open_incident_delete() returns trigger as $$
begin
    if OLD.status != 'closed' then
        raise exception 'Нельзя удалить инцидент, пока он не закрыт!';
    end if;
    return OLD;
end;
$$ language plpgsql;

create or replace function update_last_modified() returns trigger as $$
begin
    NEW.last_modified := current_timestamp;
    return NEW;
end;
$$ language plpgsql;

create or replace function escalate_critical_rule() returns trigger as $$
declare
    rule_thresh decimal;
begin
    select threshold into rule_thresh from security_rules where rule_id = NEW.rule_id;
    if rule_thresh = 0 then
        update incidents set threat_level = 5 where tx_id = NEW.tx_id;
    end if;
    return NEW;
end;
$$ language plpgsql;

-- удаляем старые триггеры перед созданием
drop trigger if exists trg_incident_audit on incidents;
drop trigger if exists trg_check_threat on incidents;
drop trigger if exists trg_prevent_delete on incidents;
drop trigger if exists trg_last_modified on incidents;
drop trigger if exists trg_escalate_critical on rule_violations;

-- создаем 5 триггеров
create trigger trg_incident_audit after insert or update on incidents for each row execute function log_incident_changes();
create trigger trg_check_threat before insert or update on incidents for each row execute function enforce_threat_level();
create trigger trg_prevent_delete before delete on incidents for each row execute function prevent_open_incident_delete();
create trigger trg_last_modified before update on incidents for each row execute function update_last_modified();
create trigger trg_escalate_critical after insert on rule_violations for each row execute function escalate_critical_rule();