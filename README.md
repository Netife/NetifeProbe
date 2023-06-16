# NetifeProbe
Netife网络探针器，负责捕获网络请求，并提供流模式的功能



### 目标功能

- 利用 MITM（中间人攻击）的方式截获数据包，提供对 http 、ws 、https 、wss 请求响应的编辑支持



### 部分实现思路

- 利用 WinDivert 提供的 api 编辑 tcp/ip 头部字段（源、目的ip；源、目的端口）以实现重定向

- 利用 mkcert 根 CA 颁发自签名证书解决浏览器警告

- MITM:

![image-20230524231336717](http://120.27.140.30:89/imgs/2023/06/image-20230524231336717.png)



### 相关依赖

- grpc，用于和其他模块对接，用于扩展。可通过 vcpkg 下载
- `WinDivert，已将头文件和 dll 放到了项目的相应位置，无需额外下载`
- mkcert，用于为 Https 代理服务器生成证书，**已打包为工具 exe 放入项目目录**
- （mswsock 库是微软提供的扩展库，windows操作系统**自带**）





### 依赖链接

grpc：https://github.com/grpc/grpc

WinDivert：https://github.com/basil00/Divert

mkcert：https://github.com/FiloSottile/mkcert

