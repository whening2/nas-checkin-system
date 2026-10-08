# NAS 签到系统

这是一个专为 NAS（如群晖）设计的轻量级扫码签到系统。支持 IPv4/IPv6，适合在 Docker 中快速部署。

## 功能特性

- 扫码签到：手机扫码即可填写姓名、电话、公司并提交。
- 后台管理：手机或电脑浏览器打开管理页面，实时查看签到记录。
- 一键导出：支持导出 CSV 表格，直接使用 Excel 打开。
- 一键生成二维码：管理后台直接生成签到二维码。

### 环境要求

- x86的docker。
- 支持 IPv6 的网络环境。

### 部署步骤

1. 在本地构建镜像并导出为 tar 文件，然后部署在docker中：

   ```bash
   DOCKER_DEFAULT_PLATFORM=linux/amd64 docker build -t checkin-server:1.0 .
   docker save -o checkin-server.tar checkin-server:1.0

2.将 checkin-server.tar 上传到 NAS，在 Container Manager 中导入。
创建容器，配置如下：

端口映射：本地端口xx → 容器端口 8080
存储空间：/docker/checkin-data → 容器路径 /data
环境变量：ADMIN_PASSWORD = 你的强密码
TZ：	Asia/Shanghai
启动容器，通过浏览器访问 http://你的域名:端口/ 即可签到。
