
SHOW GLOBAL STATUS LIKE 'Max_used_connections';
SHOW GLOBAL STATUS LIKE 'Threads_connected';
SHOW GLOBAL STATUS LIKE 'Threads_running';
SHOW GLOBAL STATUS LIKE 'Threads_created';

SHOW GLOBAL STATUS LIKE 'Created_tmp%';

SHOW GLOBAL STATUS LIKE 'Opened_tables';
SHOW GLOBAL STATUS LIKE 'Open_tables';
SHOW GLOBAL STATUS LIKE 'Opened_table_definitions';
SHOW GLOBAL STATUS LIKE 'Open_table_definitions';

SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool%';

SHOW GLOBAL VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW GLOBAL VARIABLES LIKE 'table_open_cache';
SHOW GLOBAL VARIABLES LIKE 'table_definition_cache';
SHOW GLOBAL VARIABLES LIKE 'max_connections';



SHOW GLOBAL STATUS LIKE 'Opened_tables';
SHOW GLOBAL STATUS LIKE 'Open_tables';
SHOW GLOBAL STATUS LIKE 'Opened_table_definitions';
SHOW GLOBAL STATUS LIKE 'Open_table_definitions';

-- ایجاد جداول موقت روی دیسک (Created_tmp_disk_tables):
SHOW GLOBAL STATUS LIKE 'Created_tmp_disk_tables';