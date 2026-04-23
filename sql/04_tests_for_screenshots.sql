
select * from top_vulnerabilities();

-- вставка инцидента с плохим threat_level
insert into incidents (tx_id, operator_id, status, threat_level) values (1, 1, 'open', 99);

-- проверка аудита после вставки
select * from incident_log;

-- попытка удалить инцидент
delete from incidents where status = 'open';

-- для хеширования пароля
update clients set email = md5(email) where client_id = 1;

-- показ хеша
select email from clients where client_id = 1;

-- меняем статус и пробуем поставить плохой уровень угрозы 99
update incidents set status = 'investigating', threat_level = 99 where incident_id = 1;
-- смотрим результат: время обновилось, а уровень стал 3 (это и скринь для 4.b)
select incident_id, status, threat_level, last_modified from incidents where incident_id = 1;

-- пытаемся удалить инцидент со статусом investigating (это и скринь для 4.c — должна быть ошибка)
delete from incidents where incident_id = 1;

-- сначала закроем инцидент, чтобы было что считать
update incidents set status = 'closed', last_modified = current_timestamp + interval '15 minutes' where incident_id = 1;
-- вызов функций (это и скринь для 4.d)
select avg_response_time(1) as avg_time, check_threat_level(1) as is_valid;

-- превращаем почту в хеш
update clients set email = md5(email) where client_id = 1;
-- смотрим результат (это и скринь для 4.e)
select full_name, email from clients where client_id = 1;