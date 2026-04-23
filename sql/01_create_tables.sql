-- удаляем старые таблицы, если они были, чтобы начать с чистого листа
drop table if exists rule_violations cascade;
drop table if exists blacklist cascade;
drop table if exists incident_log cascade;
drop table if exists incidents cascade;
drop table if exists transactions cascade;
drop table if exists security_rules cascade;
drop table if exists operators cascade;
drop table if exists clients cascade;

-- создание таблицы клиентов
create table clients (
    client_id serial primary key,
    full_name varchar(150) not null,
    email varchar(100) not null,
    phone varchar(20),
    reg_date timestamp default current_timestamp
);

-- создание таблицы транзакций
create table transactions (
    tx_id serial primary key,
    client_id int not null references clients(client_id),
    amount decimal(10,2) not null,
    tx_date timestamp default current_timestamp,
    ip_address varchar(45) not null,
    status varchar(50) not null default 'pending'
);

-- создание таблицы правил безопасности (уязвимостей)
create table security_rules (
    rule_id serial primary key,
    rule_name varchar(100) not null,
    description text,
    threshold decimal(15,2) not null
);

-- создание связующей таблицы нарушений правил
create table rule_violations (
    violation_id serial primary key,
    tx_id int not null references transactions(tx_id),
    rule_id int not null references security_rules(rule_id),
    detected_at timestamp default current_timestamp
);

-- создание таблицы операторов
create table operators (
    operator_id serial primary key,
    full_name varchar(150) not null,
    position varchar(100) not null
);

-- создание главной таблицы инцидентов со всеми нужными полями для триггеров
create table incidents (
    incident_id serial primary key,
    created_at timestamp default current_timestamp,
    last_modified timestamp default current_timestamp,
    incident_type varchar(100),
    threat_level int default 3,
    status varchar(50) default 'open',
    description text,
    tx_id int references transactions(tx_id),
    operator_id int references operators(operator_id),
    closed_at timestamp
);

-- создание таблицы черного списка
create table blacklist (
    blacklist_id serial primary key,
    entity_type varchar(50) not null,
    entity_value varchar(255) not null unique,
    reason text,
    added_at timestamp default current_timestamp,
    operator_id int references operators(operator_id)
);

-- создание служебной таблицы для триггера аудита
create table incident_log (
    log_id serial primary key,
    incident_id int,
    action_type varchar(50),
    old_status varchar(50),
    new_status varchar(50),
    changed_at timestamp default current_timestamp,
    changed_by varchar(100) default current_user
);