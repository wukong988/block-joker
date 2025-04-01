# Block Joker 自动化挖矿脚本

这是一个用于自动化运行 Block Joker 挖矿的本地脚本。单台电脑可同时运行最多100个账号。

## 必要条件

- 代理IP
- Yes验证码打码平台账号
- Block Joker 账号

## 相关平台链接

- Block Joker: [点击注册](https://blockjoker.org/home?invite_code=Z4r1yE780AEJoo5G7A2AIf49F5CEkQUDgIaPCvVioyE=)
- Yes验证码平台: [点击注册](https://yescaptcha.com/i/HiIywr)
- 代理IP购买: 请添加微信 `sueyj_258`

> 建议使用上方带邀请码的 Yes 验证码平台链接注册，您的消费将用于支持开发维护。

## 配置说明

### 1. 代理配置
在 `proxy.txt` 文件中填写代理IP，每行一个，格式如下：
http://用户名:密码@IP:端口

### 2. 平台配置
在 `config.json` 中填写以下信息：
- Yes验证码平台的 clientKey
- Block Joker 的 token，注意保持格式，cookie和userAgent不要删除，保持为空即可

## 使用方法

### 1. 克隆仓库
```bash
https://github.com/wukong988/block-joker.git
cd block-joker
```


### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 运行脚本
```bash
python joker.py
```



## 注意事项
- 请确保代理IP可用且稳定
- 运行前请正确配置所有必要参数
- 建议定期检查更新以获得最佳体验
- 本代码用于测试使用，请勿非法应用，造成损失概不负责