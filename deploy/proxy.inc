proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;   # не доверяем XFF клиента
proxy_set_header X-Forwarded-Proto https;
