FROM ubuntu:22.04

# docker ps -q | xargs -I {} docker inspect -f '{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {}
# docker build --no-cache -t assets-flask .
# docker run --env-file .AssetsEnv -itd -p 127.0.0.1:5020:5020 assets-flask

# 设置工作目录
WORKDIR /root

ARG FILE_NAME=assets-detect.zip
ENV FILE_NAME=${FILE_NAME}
# 复制启动脚本到容器
COPY start.sh /root/start.sh
RUN chmod +x /root/start.sh

# 安装相关依赖
RUN apt -y update
RUN apt -y install --no-install-recommends python3 unzip vim python3-pip gcc nmap screen
RUN apt-get install -y tzdata && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# 添加文件
ADD $FILE_NAME /root

# 解压文件
RUN unzip /root/$FILE_NAME -d /root

# 安装 Python 依赖
RUN pip3 install -r /root/assets-detect/requirements.txt

# 删除非项目文件
RUN rm -rf /root/$FILE_NAME
RUN rm -rf /root/__MACOSX
RUN cd /root/assets-detect && rm -rf .DS_Store .git* .idea README.md Dockerfile venv

# Expose port
EXPOSE 5020

ENTRYPOINT ["/root/start.sh"]
