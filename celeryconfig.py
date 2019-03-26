broker_url = 'pyamqp://guest@localhost//'
result_backend = 'rpc://'
task_time_limit = 10
worker_max_memory_per_child = 2048000 #2GB
accept_content = ['pickle', 'json']
result_serializer = 'pickle'
task_serializer = 'pickle'
