import asyncio
import logging
import os
import ssl
import time
import aiofiles
import aiohttp
import requests
import json
import random
import hashlib



# 根目录
ROOT_DIR = "./"

# 统计用户数
ACTIVE_USERS = set()
# 正在启动的任务数
STARTING_NUM = 0
# 已初始化的用户
INITIALIZED_USERS = set()

class Joker:
    def __init__(self, user_id: str, authToken: str, cookie: str, userAgent: str, proxy: str, clientKey: str):
        self.authToken = authToken
        self.cookie = cookie
        self.userAgent = userAgent
        self.proxy = proxy
        self.user_id = user_id # 模拟一个吧
        self.clientKey = clientKey
        self.session: aiohttp.ClientSession = aiohttp.ClientSession(trust_env=True,
                                                                    connector=aiohttp.TCPConnector(ssl=False))
        self.setup_logger()
            
    def setup_logger(self):
        """设置日志配置"""
        self.logger = logging.getLogger(f"{self.user_id}")
        self.logger.setLevel(logging.INFO)
        # 设置不传播到父logger
        self.logger.propagate = False
        
        # 创建文件处理器
        fh = logging.FileHandler(f'{ROOT_DIR}/joker_run.log', encoding='utf-8')
        fh.setLevel(logging.INFO)
        
        # # 创建控制台处理器
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # 创建格式器
        formatter = logging.Formatter('%(asctime)s-[%(name)s]-%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        # 添加处理器到日志记录器
        if not self.logger.handlers:
            self.logger.addHandler(fh)
            self.logger.addHandler(ch)

    # 创建过验证码任务
    async def create_cf_task(self, clientKey: str) -> str:
        try:
            
            # 添加SSL上下文配置
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            url = "https://api.yescaptcha.com/createTask"
            body = {
                "clientKey": clientKey,
                "task": {
                    "type": "CloudFlareTaskS3",
                    "websiteURL": "https://blockjoker.org",
                    "proxy": self.proxy
                },
                "softID": "54751",
            }
            


            # 使用aiohttp请求, 创建一个新的session
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=body, proxy=self.proxy, ssl=ssl_context) as response:
                    response_text = await response.text()
                    result = json.loads(response_text)
                    return result["taskId"]
        except Exception as e:
            self.logger.error(f"create_cf_task 异常: {e}")
            return None

        # response = requests.post(url, json=body, proxies=proxies)
        # self.logger.info(f"创建 cf task::{response.text}")
        # result = json.loads(response.text)
        # return result["taskId"]

    # 检查验证码是否通过
    async def check_cf(self, taskId: str, clientKey: str):
        try:
            
            # 添加SSL上下文配置
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            body = {"clientKey": clientKey, "taskId": taskId, "softID": "54751"}
            url = "https://api.yescaptcha.com/getTaskResult"
            # 使用aiohttp请求, 创建一个新的session
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=body, proxy=self.proxy, ssl=ssl_context) as response:
                    response_text = await response.text()
                    result = json.loads(response_text)
                    return result
        except Exception as e:
            self.logger.error(f"check_cf 异常: {e}")
            return None

        # response = requests.post(url, json=body, proxies=proxies)
        # self.logger.info(f"检查 cf task::{response.text}")

        # result = json.loads(response.text)
        # """ 响应参数
        #     {
        #         "errorId": 0,  // errorId>0 表示失败
        #         "errorCode": null,
        #         "errorDescription": null,
        #         "solution": {
        #             "token": "0.ufq5RgSVZd11DPSX1brdrxnEs28KcVlKj2ORchqxSy2q9yAW6ciq3hriXDF4x……",
        #             "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36", 
        #         },
        #         "status": "ready"  // processing：正在识别中，请3秒后重试    ready：识别完成，在solution参数中找到结果

        #     }
        # """
        # return result
    
    async def change_proxy(self):
        # 读取代理 1行一个代理 格式:http://username:password@127.0.0.1:1080
        with open("./proxy.txt", "r") as f:
            proxy_list = f.readlines()
        if len(proxy_list) == 0:
            self.logger.error("代理列表为空")
            return
        # 随机一个代理
        self.proxy = proxy_list[random.randint(0, len(proxy_list) - 1)].strip()

    # cf打码
    async def cf_captcha(self):
        # 进行5次尝试
        for index in range(10):
            self.logger.info("检测到CloudFlare验证，尝试处理验证码...")
            # 创建验证码任务
            taskId = await self.create_cf_task(self.clientKey)
            if taskId is None:
                continue
            for i in range(50):
                result = await self.check_cf(taskId, self.clientKey)
                if result is None:
                    continue
                if "errorId" in result and result["errorId"] > 0:
                    self.logger.error(f"打码失败: {result}")
                    # if "errorCode" in result and result["errorCode"] == "ERROR_CAPTCHA_UNSOLVED":
                    #     # 可能是代理ip质量不行。换一个
                    #     await self.change_proxy()
                    break
                if result["status"] == "ready":
                    return result
                
                await asyncio.sleep(3)
            await asyncio.sleep(15)
        return None

    # async def get_cf_token(self):
    #     result = await self.cf_captcha()


    async def http_request(self, url, method, data, proxy = None):
        try: 
            if proxy is None:
                proxy = self.proxy
            # 请求头
            headers = {
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'zh-CN,zhq=0.9,enq=0.8,beq=0.7',
                'Authorization': self.authToken,
                'Cache-Control': 'no-cache',
                'Cookie': self.cookie,
                'Pragma': 'no-cache',
                'Priority': 'u=1, i',
                'Referer': 'https://blockjoker.org/home',
                'Sec-Ch-Ua': '"Chromium";v="128", "Not=A=Brand";v="24", "Google Chrome";v="128"',
                'Sec-Ch-Ua-Arch': '"x86"',
                'Sec-Ch-Ua-Bitness': '"64"',
                'Sec-Ch-Ua-Full-Version': '"128.0.6613.138"',
                'Sec-Ch-Ua-Full-Version-List': '"Chromium";v="128.0.6613.138", "Not=A=Brand";v="24.0.0.0", "Google Chrome";v="128.0.6613.138"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Model': '""',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Sec-Ch-Ua-Platform-Version': '"15.0.0"',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'User-Agent': self.userAgent
            }

            # 添加SSL上下文配置
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            async with self.session.request(method, url, json=data, headers=headers, proxy=proxy, ssl=ssl_context) as response:
                # 检查响应状态
                self.logger.info(f"响应状态码: {response.status}")
                # self.logger.info(f"响应头: {dict(response.headers)}")
                
                if response.status == 403:
                    cf_result = await self.cf_captcha()
                    if cf_result and "solution" in cf_result:
                        # 从返回的solution中获取cookie和user agent
                        cf_cookies = cf_result['solution']['cookies']
                        new_cookie = f"__cflb={cf_cookies['__cflb']}; cf_clearance={cf_cookies['cf_clearance']}"
                        self.cookie = new_cookie
                        # 更新user agent
                        new_user_agent = cf_result['solution']['user_agent']
                        self.userAgent = new_user_agent  # 更新实例的user agent
                        
                        # 使用新的headers重试请求
                        async with self.session.request(method, url, json=data, headers=headers, ssl=ssl_context) as retry_response:
                            response = retry_response
                    else:
                        self.logger.error("CloudFlare验证失败")
                        return {"ok": False, "error": "打码失败。。。"}
                

                # 检查内容编码
                if 'Content-Encoding' in response.headers:
                    self.logger.info(f"内容编码: {response.headers['Content-Encoding']}")
                    
                    # 获取响应内容
                    content = await response.read()
                    
                    # 如果是 br 编码且未自动解码
                    if response.headers['Content-Encoding'] == 'br' and not content.startswith(b'{'):
                        try:
                            import brotli
                            decoded_content = brotli.decompress(content)
                            self.logger.info("成功使用 brotli 解码响应内容")
                            result = json.loads(decoded_content)
                        except ImportError:
                            self.logger.error("http_request 未安装 brotli 库，请运行 'pip install brotli' 安装")
                            raise
                        except Exception as e:
                            self.logger.error(f"http_request 解码 brotli 内容时出错: {e}")
                            self.logger.error(f"http_request 原始内容前100个字节: {content[:100]}")
                            raise
                    else:
                        # 尝试解析JSON
                        text = await response.text()
                        result = json.loads(text)
                else:
                    # 没有压缩，直接解析
                    result = await response.json()
        except json.JSONDecodeError:
                self.logger.error("响应不是有效的JSON格式:")
                self.logger.error(f"状态码: {response.status}")
                self.logger.error(f"响应头: {dict(response.headers)}")
                text = await response.text()
                self.logger.error(f"响应内容前100个字符: {text[:100] if text else '空'}")     
                result = {
                    "ok": False,
                    "error": "响应不是有效的JSON格式"
                }
        # 如果是time out 则换一个代理
        except aiohttp.ClientError as e:
            self.logger.error(f"http_request 代理错误: {e}")
            await self.change_proxy()
            result = {
                "ok": False,
                "error": f"代理异常：{self.proxy}"
            }
        except Exception as e:
            self.logger.error(f"http_request 发生错误: {e}")
            result = {
                "ok": False,
                "error": str(e)
            }
        return result

    # 生成随机字符串
    async def generate_random_string(self, length):
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return ''.join(random.choice(chars) for _ in range(length))

    # 计算SHA-256哈希
    async def calculate_hash(self, text):
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    # 挖矿函数
    async def mine(self, payload, require):
        self.logger.info(f"开始挖矿: user_id={self.user_id} payload={payload}, require={require}")
        
        # 将计算密集型任务包装在一个同步函数中
        def mining_task():
            count = 0
            start_time = time.time()
            while True:
                # 生成随机字符串
                nonce = ''.join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(48))
                
                # 计算哈希
                hash_value = hashlib.sha256((payload + nonce).encode('utf-8')).hexdigest()
                
                # 计数
                count += 1
                if count % 10000 == 0:
                    elapsed = time.time() - start_time
                    hashrate = count / elapsed
                    self.logger.info(f"已计算 {count} 次哈希，算力: {hashrate:.2f} H/s")
                
                # 检查是否满足条件
                if hash_value.startswith(require):
                    elapsed = time.time() - start_time
                    self.logger.info(f"\n找到符合条件的nonce: {nonce}")
                    self.logger.info(f"对应的哈希值: {hash_value}")
                    self.logger.info(f"总计算次数: {count}")
                    self.logger.info(f"耗时: {elapsed:.2f} 秒")
                    self.logger.info(f"平均算力: {count/elapsed:.2f} H/s")
                    return nonce, hash_value

        # 使用 asyncio.to_thread 在线程池中执行计算密集型任务
        return await asyncio.to_thread(mining_task)

    async def run_joker(self):
        try:
            global STARTING_NUM
            # 获取挖矿任务
            self.logger.info("正在获取挖矿任务...")
            url = "https://blockjoker.org/api/v2/missions"
            
            # 添加处理压缩内容的逻辑
            result = await self.http_request(url, "POST", {})
            
                
            self.logger.info(f"任务数据: {json.dumps(result, indent=2, ensure_ascii=False)}")
            
            if result.get("ok") and "result" in result:
                # 任务获取成功，如果用户未被记录过，则减少启动计数
                if self.user_id not in INITIALIZED_USERS:
                    INITIALIZED_USERS.add(self.user_id)
                    STARTING_NUM = max(0, STARTING_NUM - 1)

                payload = result["result"]["payload"]
                require = result["result"]["require"]
                # 统计用户数
                ACTIVE_USERS.add(self.user_id)
                
                # 开始挖矿
                nonce, hash_value = await self.mine(payload, require)
                
                # 生成随机任务ID
                rid = random.randint(100000000, 999999999)
                
                # 提交结果
                self.logger.info(f"\n正在提交结果，任务ID: {rid}")
                submit_url = "https://blockjoker.org/api/v2/missions/nonce"
                submit_data = {"nonce": nonce, "rid": rid}
                
                self.logger.info(f"提交数据: {json.dumps(submit_data, indent=2)}")
                
                submit_result = await self.http_request(
                    submit_url, 
                    "POST", 
                    submit_data
                )
                
                self.logger.info(f"提交响应内容: {submit_result}")
                
                # 检查版本
                version_url = "https://blockjoker.org/api/v2/version"
                version_result = await self.http_request(version_url, "GET", {})
                self.logger.info(f"版本信息: {version_result}")
                return True
            else:
                ACTIVE_USERS.discard(self.user_id)
                self.logger.info(f"获取任务失败: {result}")
                return False
        except Exception as e:
            ACTIVE_USERS.discard(self.user_id)
            self.logger.error(f"run_joker 发生错误: {e}")

    # 主函数
    async def start(self):
        while True:
            try:
                await self.run_joker()
            except Exception as e:
                self.logger.error(f"start 发生错误: {e}")
            await asyncio.sleep(1)

async def truncate_log_file(file_path: str, max_size: int = 300 * 1024 * 1024 ):
    """安全地清空日志文件"""
    try:
        if os.path.exists(file_path) and os.path.getsize(file_path) > max_size:
            # 使用 'w' 模式打开文件并立即关闭，这会清空文件内容
            with open(file_path, 'w') as f:
                pass
            print(f"已清空日志文件: {file_path}", flush=True)
    except Exception as e:
        print(f"清空日志文件 {file_path} 失败: {e}", flush=True)

async def save_active_users_count():
    start_time = time.time()
    start_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))
    while True:
        try:
            
            # 安全地清空日志文件
            # await truncate_log_file(f"{ROOT_DIR}/joker_run.log")
            async with aiofiles.open("./统计用户数.txt", "w", encoding="utf-8") as f:
                current_time = time.strftime("%Y-%m-%d %H:%M:%S")
                content = f"开始时间：{start_time_str} \n"
                content += f"更新时间：{current_time} \n"
                content += f"当前活跃用户数：{len(ACTIVE_USERS)}\n"
                await f.write(content)
            
            # 写完文件后等待一段时间
            await asyncio.sleep(10)
            
        except Exception as e:
            print(f"保存数据文件失败: {e}", flush=True)
            # 发生错误时等待较长时间
            await asyncio.sleep(30)

async def main():
    # # 读取token.json
    # with open("./token.json", "r") as f:
    #     token_list = json.load(f)

    # 去https://yescaptcha.com/i/HiIywr 注册打码账号，并且充值10元
    # 读取config.json
    with open("./config.json", "r") as f:
        config = json.load(f)
    token_list = config["token"]
    clientKey = config["clientKey"]


    # 读取代理 1行一个代理 格式:http://username:password@127.0.0.1:1080
    with open("./proxy.txt", "r") as f:
        proxy_list = f.readlines()
    if len(token_list) > len(proxy_list):
        print("代理ip数量必须大于token数量")
        return

    print(f"共加载到{len(token_list)}个token")

    index = 0
    # 给每个账号分配一个ip
    for token in token_list:
        # 按顺序分配吧
        proxy = proxy_list[index].strip()
        token["proxy"] = proxy
        index += 1

    # 遍历token_list 使用批量异步运行start
    tasks = []
    index = 0

    # 统计用户数
    status_task = asyncio.create_task(save_active_users_count())
    tasks.append(status_task)

    # 分批次
    batch_size = 10
    for i in range(0, len(token_list), batch_size):
        batch_token_list = token_list[i:i+batch_size]
        batch_tasks = []

        for token in batch_token_list:
            global STARTING_NUM
            STARTING_NUM += 1
            # user_id 为空时，随机生成一个
            user_id = token["user_id"] if "user_id" in token and token["user_id"] is not None else f"用户{index}"
            # 开启异步线程
            joker = Joker(user_id=user_id, authToken=token["authToken"], cookie=token["cookie"], userAgent=token["userAgent"], proxy=token["proxy"], clientKey=clientKey)    
            batch_tasks.append(asyncio.create_task(joker.start()))
            index += 1
        
        tasks.extend(batch_tasks)
        print(f"正在启动第 {i//batch_size + 1} 批用户（{len(batch_tasks)}个）", flush=True)
        # 等待所有任务初始化完成
        while STARTING_NUM > 0:
            await asyncio.sleep(5)
            print(f"♻️ 等待任务初始化完成，第 {i//batch_size + 1} 批还剩 {STARTING_NUM} 个任务...", flush=True)
        
        # # 等待10秒再启动下一批
        # await asyncio.sleep(60)
        print(f"第 {i//batch_size + 1} 批用户已全部启动; 开始下一批", flush=True)
    

    # # 等待所有任务完成
    await asyncio.gather(*tasks)
    
    


if __name__ == "__main__":
    asyncio.run(main())
