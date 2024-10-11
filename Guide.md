# Setup & update StatusServer

```
adduser --system --shell /usr/sbin/nologin --home /home/statusserv --create-home statusserv
chown www-data:www-data /home/statusserv/
```

## python create virtual environment

```
sudo apt install python3-venv

cd /home/statusserv
git clone https://github.com/Crasher508/status-page.git
python -m venv venv

source venv/bin/activate
pip install -r requirements.txt
deactivate
```

## schedule status checks

```
crontab -e and follow the tutorial here.
*/5 * * * * /home/statusserv/venv/bin/python /home/statusserv/cron.py
```

## setup nginx

```
nano /etc/nginx/sites-available/status.conf
```

```
server {
    server_name status.XXXXXX.de;

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Scheme $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        include uwsgi_params;
        uwsgi_pass unix:/home/statusserv/statusserv.sock;
    }

    listen 443 ssl http2;
    ssl_certificate ;
    ssl_certificate_key ;
}
server {
    if ($scheme = "http") {
        return 301 https://$host$request_uri;
    }
    listen 80;
    server_name status.XXXXXX.de;
    return 404;
}
```

```
sudo ln -s /etc/nginx/sites-available/status.conf /etc/nginx/sites-enabled/status.conf
nginx -t
systemctl restart nginx
```

## start server
### start without service e.g. with screen:

```
cd /home/statusserv
chmod +x start.sh
screen -R StatusServer ./start.sh
```

### start with service:

```
cp statusserv.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable statusserv
systemctl start statusserv
```

# Update

```
python3 -m venv --upgrade venv
venv/bin/pip list --outdated
for i in $(venv/bin/pip list -o | awk 'NR > 2 {print $1}'); do venv/bin/pip install $i --upgrade; done
venv/bin/pip freeze > requirements.txt
```