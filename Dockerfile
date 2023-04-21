# 选择一个基础镜像
FROM golang:1.18-alpine

# 设置工作目录
WORKDIR /app

# 复制源代码到镜像中
COPY . .
# 构建应用程序
RUN go build -o app .

# 设置容器启动命令
CMD ["/app/app"]