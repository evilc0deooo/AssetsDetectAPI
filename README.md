## AssetsDetectAPI

此项目参考了 arl、oneforall、xunfeng 等优秀项目代码。

## 创建启动 Redis 容器

```bash
docker pull redis:latest
docker run -d --name redis -p 6379:6379 redis:latest --requirepass "redis_password"
```

## 创建启动 Mongo 容器

```bash
docker pull mongo
docker run -d \
  --name mongodb \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=mongo_password \
  mongo
```

## 部署项目

Python 3.9.6

```bash
apt -y update && apt-get -y install gcc python3-dev
apt -y install nmap
python3 -m pip install -r requirements.txt

celery -A celerytask.celery worker -l debug -Q assets_task -n celery_task -c 2 -O fair -f logs/celery.log
gunicorn -b 127.0.0.1:5020 --workers 3 app:app --access-logfile logs/access.log
```