-- добавляем клиентов
insert into clients (full_name, email, phone) values
('Иванов Иван', 'ivan@mail.ru', '+79991234567'),
('Смирнова Анна', 'anna@yandex.ru', '+79009876543'),
('Петров Алексей', 'petrov@gmail.com', '+79112223344');

-- добавляем правила антифрод-системы
insert into security_rules (rule_name, description, threshold) values
('Превышение лимита', 'Транзакция больше 100000 руб', 100000.00),
('Подозрительный IP', 'Платеж с зарубежного IP адреса', 0),
('Частые переводы', 'Более 3 переводов за 10 минут', 3);

-- добавляем операторов
insert into operators (full_name, position) values
('Холодов Р.Д.', 'Старший аналитик'),
('Сидоров Олег', 'Офицер безопасности');

-- добавляем транзакции
insert into transactions (client_id, amount, ip_address, status) values
(1, 1500.50, '192.168.1.15', 'completed'),
(2, 250000.00, '45.33.22.11', 'blocked'),
(3, 500.00, '10.0.0.5', 'completed'),
(1, 120000.00, '188.11.22.33', 'pending');

-- фиксируем нарушения
insert into rule_violations (tx_id, rule_id) values
(2, 1),
(2, 2),
(4, 1);

-- создаем инциденты для ручного разбора
insert into incidents (incident_type, tx_id, operator_id, status) values
('Подозрительная активность', 2, 1, 'investigating'),
('Крупный перевод', 4, 2, 'open');

-- заносим данные в черный список
insert into blacklist (entity_type, entity_value, reason, operator_id) values
('ip_address', '45.33.22.11', 'Мошенническая атака с краденой карты', 1);