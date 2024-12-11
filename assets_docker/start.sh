#!/bin/bash

# 启动 Celery worker 在 screen 中
cd /root/assets-detect/ && screen -dmS celery_task celery -A celerytask.celery worker -l debug -Q assets_task -n celery_task -c 2 -O fair

# 启动 Flask 应用
python3 /root/assets-detect/app.py
