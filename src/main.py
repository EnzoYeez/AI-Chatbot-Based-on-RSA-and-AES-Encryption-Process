# python "C:\Users\Yeez\Desktop\计算机安全\精简\main.py"
# ===== 标准库 =====
import os
import sys
import io
import re
import json
import time
import random as r
import locale

# ===== 第三方库 =====
import requests as rq
from cryptography.hazmat.backends import default_backend
from openai import OpenAI
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sympadding

# ===== 项目依赖（Napcat + 本地模块）=====
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from ncatbot.core.client import BotClient
from ncatbot.core.message import *
from ncatbot.core.element import *
from ncatbot.utils.config import config, get_log
from RSA_Encrypt import encrypt_text, decrypt_text, gen_key
# from word2picture import xunfeipic  # 如需要图生图功能可取消注释

# ===== 环境变量与编码设置 =====
# 强制环境使用 UTF-8，避免 ascii 编码错误（尤其是 header）
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["LC_ALL"] = "C.UTF-8"
try:
    locale.setlocale(locale.LC_ALL, 'C.UTF-8')
except locale.Error:
    pass  # Windows 会报错，忽略即可

# 设置标准输入输出为 UTF-8（防止控制台乱码）
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')

# ===== 全局变量与配置初始化 =====
encrypt_status = {}  # 存储加密状态和AES密钥

my_public_key = None
my_private_key = None
_log = get_log()

config.set_bot_uin("2401262719")
config.set_root("2490162471")
config.set_ws_uri("ws://localhost:3001")
config.set_ws_token("")
config.set_webui_uri("http://localhost:6099")
config.set_webui_token("napcat")

bot = BotClient()

client = OpenAI(
    api_key="sk-9c68dc233a6147aa922d1a3e18e16dc8",
    base_url="https://api.deepseek.com",
    default_headers={
        "User-Agent": "YamadaAnna",  # 英文 ASCII-only 名称
        "X-Client-Name": "YamadaAnna"
    }
)



# ===== 全局状态追踪器 =====
class Parameters():
    saylastTime = 0
    freshlastTime = 0

# ===== 系统预设角色（ChatGPT上下文）=====
premise = [{
    "role": "system",
    "content": (
        "你是一个友好的AI助手，名字是山田杏奈。你的任务是回答用户的问题，提供有用的信息和建议。"
        "你可以处理各种主题，包括但不限于技术、娱乐、生活等。"
        "请用简洁清晰的语言回答用户的问题，尽量控制在50字以内。"
    )
}]


# ===== 辅助函数工具区 =====
def isActionTime(lastTime, interval):
    if lastTime == 0:
        return True
    return time.time() - lastTime >= interval

def read_json(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_json(file_path, data):
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def remove_markdown(text):
    text = re.sub(r'#+\s*', '', text)  # 删除标题符号
    text = re.sub(r'[*_]{1,3}', '', text)  # 删除强调符号
    text = re.sub(r'[-+*]\s*|\d+\.\s*', '', text)  # 删除列表
    text = re.sub(r'^>\s*', '', text, flags=re.MULTILINE)  # 引用
    text = re.sub(r'[-*]{3,}', '', text)  # 分隔线
    text = re.sub(r'\|[^|]+\|', '', text)  # 表格
    text = re.sub(r'```|`', '', text)  # 行内代码块
    return text

def set_encrypt_status(target_id: str, is_group: bool, value: bool,
                      aes_key: bytes = None, peer_pem: str = None):  # 新增peer_pem参数
    key = f"group_{target_id}" if is_group else f"user_{target_id}"
    if value:
        encrypt_status[key] = {
            'enabled': True,
            'aes_key': aes_key,
            'peer_pem': peer_pem  # 存储PEM字符串
        }
    else:
        encrypt_status[key] = {'enabled': False}

def get_encrypt_status(target_id: str, is_group: bool) -> bool:
    key = f"group_{target_id}" if is_group else f"user_{target_id}"
    return encrypt_status.get(key, {}).get('enabled', False)

def get_aes_key(target_id: str, is_group: bool) -> bytes:
    key = f"group_{target_id}" if is_group else f"user_{target_id}"
    return encrypt_status.get(key, {}).get('aes_key', None)

def generate_aes_key():
    """生成随机的256位AES密钥"""
    return os.urandom(32)

def get_peer_pem(target_id: str, is_group: bool) -> str:
    key = f"group_{target_id}" if is_group else f"user_{target_id}"
    return encrypt_status.get(key, {}).get('peer_pem')


def aes_encrypt(plaintext: str, key: bytes) -> str:
    """使用AES-GCM模式加密文本"""
    # 将文本编码为字节
    plaintext_bytes = plaintext.encode('utf-8')

    # 添加PKCS7填充
    padder = sympadding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()

    # 生成随机nonce
    nonce = os.urandom(12)

    # 创建加密器
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # 加密并获取标签
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    tag = encryptor.tag

    # 组合nonce + 标签 + 密文
    encrypted_data = nonce + tag + ciphertext

    # 返回Base64编码的字符串
    return base64.b64encode(encrypted_data).decode('utf-8')


def aes_decrypt(ciphertext: str, key: bytes) -> str:
    """使用AES-GCM模式解密文本"""
    try:
        # 解码Base64
        encrypted_data = base64.b64decode(ciphertext)
        print(f"解密数据长度: {len(encrypted_data)}字节")

        # 拆分nonce、标签和密文
        nonce = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext_bytes = encrypted_data[28:]
        print(f"Nonce: {nonce.hex()}, Tag: {tag.hex()}")

        # 创建解密器
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # 解密
        padded_plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()

        # 移除填充
        unpadder = sympadding.PKCS7(128).unpadder()
        plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext_bytes.decode('utf-8')
    except Exception as e:
        print(f"❌❌ AES解密详细错误: {type(e).__name__}: {str(e)}")
        raise



# ===== 消息发送工具（群聊/私聊，一句话说完） =====
async def sayText(ct, types, msg):
    if types == "private":
        await bot.api.post_private_msg(msg.user_id, text=ct)
    elif types == "group":
        await bot.api.post_group_msg(msg.group_id, text=ct)


# ===== 群聊事件处理器 =====
@bot.group_event(["text", "image"])
async def on_group_message(msg: GroupMessage):
    # ------ 🔐🔐 加密通信指令 ------
    if msg.raw_message.startswith("加密通信模式on:"):
        try:
            pem_data = msg.raw_message[len("加密通信模式on:"):].strip()
            peer_public_key = serialization.load_pem_public_key(pem_data.encode('utf-8'))

            if peer_public_key:
                # 生成新的AES密钥
                aes_key = generate_aes_key()

                # 用对方的公钥加密AES密钥
                encrypted_aes_key = peer_public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # 设置加密状态并保存AES密钥
                set_encrypt_status(
                    msg.group_id,
                    True,
                    True,
                    aes_key,
                    peer_pem=pem_data
                )

                # 发送加密后的AES密钥
                await bot.api.post_group_msg(msg.group_id, text=base64.b64encode(encrypted_aes_key).decode('utf-8'))

        except Exception as e:
            print("❌ 加密模式开启失败:", e)
            set_encrypt_status(msg.group_id, True, False)
            await bot.api.post_group_msg(msg.group_id, text=f"加密失败：{e}")

    elif msg.raw_message == "加密通信模式off":
        set_encrypt_status(msg.group_id, True, False)
        await bot.api.post_group_msg(msg.group_id, text="已关闭加密通信模式。")

    # ------ 📦 功能API与互动类指令 ------
    elif msg.raw_message.startswith("文字转二维码"):
        text = msg.raw_message.replace("文字转二维码", "")
        url = f"https://uapis.cn/api/textqrcode?text={text}"
        try:
            qrcode_url = rq.get(url).json()["qrcode"]
            message = MessageChain([
                Text("[文字转二维码]"),
                Image(qrcode_url),
                Text("# 来自UAPI\n# https://uapis.cn/")
            ])
        except Exception as e:
            message = MessageChain([Text(f"[ERROR] 二维码生成失败：{e}")])
        await bot.api.post_group_msg(msg.group_id, rtf=message)

    elif msg.raw_message == "给我点赞":
        try:
            await bot.api.send_like(user_id=msg.user_id, times=10)
            await bot.api.post_group_msg(msg.group_id, text=f"[INFO] 点赞成功!")
        except Exception:
            await bot.api.post_group_msg(msg.group_id, text=f"[ERROR] 点赞失败!")

    elif msg.raw_message == "项目stars":
        url = "https://api.github.com/repos/liyihao1110/NcatBot"
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/vnd.github.v3+json'
        }
        try:
            res = rq.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                stars = res.json().get("stargazers_count", "未知")
                await bot.api.post_group_msg(msg.group_id, text=f"Star数量: {stars}")
            else:
                msg = res.json().get("message", "请求失败")
                await bot.api.post_group_msg(msg.group_id, text=f"GitHub请求失败：{msg}")
        except Exception as e:
            await bot.api.post_group_msg(msg.group_id, text=f"[ERROR] 获取失败：{e}")

    # ------ 🤖 群聊 LLM 问答交互 ------
    else:
        trigger = False
        content = msg.raw_message
        if msg.message[0]["type"] == "at" and msg.message[0]["data"]["qq"] == str(msg.self_id):
            trigger = True
            content = re.sub(r'\[.*?\]', "", content).strip()
            if "@山田杏奈" in content:
                content = content.replace("@山田杏奈", "")
        elif "山田杏奈" in content:
            trigger = True
            content = content.replace("@山田杏奈", "", 1)

        if trigger:
            if isActionTime(Parameters.freshlastTime, 600):
                Parameters.freshlastTime = time.time()

            is_encrypted = get_encrypt_status(msg.group_id, True)
            aes_key = get_aes_key(msg.group_id, True)

            if content.strip() in ["", " ", ".", "。", "!", "？", "..."]:
                await bot.api.post_group_msg(msg.group_id, text="你什么都没说喵~ 有什么想问山田杏奈的？我很愿意听你说~ 🐱")
                return

            # 解密消息（如果处于加密模式）
            if is_encrypted and aes_key:
                try:
                    content = aes_decrypt(content, aes_key)
                except Exception as e:
                    print(f"❌ AES解密失败: {e}")
                    await bot.api.post_group_msg(msg.group_id, text="消息解密失败，请检查加密设置")
                    return

            # 读取历史、解密、生成回复
            filepath = f"./logs/{msg.user_id}.json"
            if os.path.exists(filepath):
                history = read_json(filepath)
            else:
                history = premise.copy()
                history.append({
                    "role": "assistant",
                    "content": "你好呀，我是山田杏奈~ 是一个友好、有礼貌的AI助手，随时为你解答问题，聊聊生活、技术、娱乐都可以喵~"
                })



            history.append({"role": "user", "content": content})
            response = client.chat.completions.create(model="deepseek-chat", messages=history, max_tokens=3000)
            answer = remove_markdown(response.choices[0].message.content)
            history.append({"role": "assistant", "content": answer})

            # 加密回复（如果处于加密模式）
            if is_encrypted and aes_key:
                try:
                    # 从状态中获取PEM数据
                    pem_data = get_peer_pem(msg.user_id, True)
                    if not pem_data:
                        raise ValueError("未找到对方公钥信息")

                    # 生成新的AES密钥
                    new_aes_key = generate_aes_key()

                    # 用新AES密钥加密回复内容
                    encrypted_answer = aes_encrypt(answer, new_aes_key)

                    # 用对方的公钥加密新的AES密钥
                    peer_public_key = serialization.load_pem_public_key(pem_data.encode('utf-8'))
                    encrypted_new_key = peer_public_key.encrypt(
                        new_aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    # 更新AES密钥
                    set_encrypt_status(msg.group_id, True, True, new_aes_key)

                    # 组合P1（新密钥）和P2（回复）
                    final_answer = f"{base64.b64encode(encrypted_new_key).decode('utf-8')}|{encrypted_answer}"
                except Exception as e:
                    print(f"❌ 加密失败: {e}")
                    final_answer = "消息加密失败，请检查加密设置"
            else:
                final_answer = answer

            await sayText(final_answer, "group", msg)
            write_json(filepath, history)

# ===== 私聊事件处理器 =====
@bot.private_event(["text", "image"])
async def on_private_message(msg: PrivateMessage):
    content = msg.raw_message

    # ------ 🎴 媒体类关键词响应 ------
    if content == "acg随机图":
        message = MessageChain([
            Text("[ACG 随机图]"),
            Image(r.choice([
                "https://uapis.cn/api/imgapi/acg/pc.php",
                "https://uapis.cn/api/imgapi/acg/mb.php"
            ])),
            Text("# 来自UAPI\n# https://uapis.cn/")
        ])
        await bot.api.post_private_msg(msg.user_id, rtf=message)

    elif content == "bing每日壁纸":
        message = MessageChain([
            Text("[Bing 每日壁纸]"),
            Image("https://uapis.cn/api/bing.php"),
            Text("# 来自UAPI\n# https://uapis.cn/")
        ])
        await bot.api.post_private_msg(msg.user_id, rtf=message)

    elif content.startswith("文字转二维码"):
        text = content.replace("文字转二维码", "")
        url = f"https://uapis.cn/api/textqrcode?text={text}"
        try:
            qrcode_url = rq.get(url).json()["qrcode"]
            message = MessageChain([
                Text("[文字转二维码]"),
                Image(qrcode_url),
                Text("# 来自UAPI\n# https://uapis.cn/")
            ])
        except Exception as e:
            message = MessageChain([
                Text(f"[ERROR] 二维码生成失败：{e}")
            ])
        await bot.api.post_private_msg(msg.user_id, rtf=message)

    # ------ 🔐🔐 加密通信开启/关闭 ------
    elif content.startswith("加密通信模式on:"):
        try:
            pem_data = content[len("加密通信模式on:"):].strip()
            peer_public_key = serialization.load_pem_public_key(pem_data.encode('utf-8'))

            if peer_public_key:
                # 生成新的AES密钥
                aes_key = generate_aes_key()

                # 用对方的公钥加密AES密钥
                encrypted_aes_key = peer_public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # 设置加密状态
                set_encrypt_status(
                    msg.user_id,
                    False,
                    True,
                    aes_key,
                    peer_pem=pem_data
                )

                # 发送加密后的AES密钥
                await bot.api.post_private_msg(msg.user_id, text=base64.b64encode(encrypted_aes_key).decode('utf-8'))

        except Exception as e:
            set_encrypt_status(msg.user_id, False, False)
            print(f"❌ 私聊加密模式开启失败：{e}")
            await bot.api.post_private_msg(msg.user_id, text=f"加密失败：{e}")


    elif content == "加密通信模式off":
        set_encrypt_status(msg.user_id, False, False)
        await bot.api.post_private_msg(msg.user_id, text="已关闭加密通信模式。")

    # ------ 🤖 私聊 AI 问答逻辑 ------
    else:
        if content.strip() in ["", " ", ",", "。", "?", "..."]:
            await bot.api.post_private_msg(msg.user_id, text="你刚刚没说话呢喵~ 有任何问题都可以问我呀！😊")
            return

        filepath = f"./logs/{msg.user_id}.json"
        history = read_json(filepath) if os.path.exists(filepath) else premise.copy()

        # 检查加密状态
        is_encrypted = get_encrypt_status(msg.user_id, False)
        aes_key = get_aes_key(msg.user_id, False)

        # 解密消息（如果处于加密模式）
        if is_encrypted and aes_key:
            try:
                content = aes_decrypt(content, aes_key)
            except Exception as e:
                print(f"❌ 私聊消息解密失败：{e}")
                await bot.api.post_private_msg(msg.user_id, text="消息解密失败，请检查加密设置")
                return

        history.append({"role": "user", "content": content})
        response = client.chat.completions.create(model="deepseek-chat", messages=history, max_tokens=3000)
        answer = remove_markdown(response.choices[0].message.content)
        history.append({"role": "assistant", "content": answer})

        # 加密回复（如果处于加密模式）
        if is_encrypted and aes_key:
            try:
                # 从状态中获取PEM数据
                pem_data = get_peer_pem(msg.user_id, False)
                if not pem_data:
                    raise ValueError("未找到对方公钥信息")

                # 生成新的AES密钥
                new_aes_key = generate_aes_key()

                # 用新AES密钥加密回复内容
                encrypted_answer = aes_encrypt(answer, new_aes_key)

                # 用对方的公钥加密新的AES密钥
                peer_public_key = serialization.load_pem_public_key(pem_data.encode('utf-8'))
                encrypted_new_key = peer_public_key.encrypt(
                    new_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # 更新AES密钥
                set_encrypt_status(msg.user_id, False, True, new_aes_key,peer_pem=pem_data)

                # 组合P1（新密钥）和P2（回复）
                final_answer = f"{base64.b64encode(encrypted_new_key).decode('utf-8')}|                |{encrypted_answer}"
            except Exception as e:
                print(f"❌ 私聊消息加密失败：{e}")
                final_answer = "消息加密失败，请检查加密设置"
        else:
            final_answer = answer

        await sayText(final_answer, "private", msg)
        write_json(filepath, history)

# ===== 群通知事件：欢迎新成员 =====
@bot.notice_event()
async def notice_event(msg):
    if msg["notice_type"] == "group_increase":
        import datetime
        if msg["sub_type"] == "approve":
            try:
                t = await bot.api.get_stranger_info(user_id=msg["user_id"])
                nickname = t["data"]["nickname"]
                now_time = datetime.datetime.strftime(datetime.datetime.now(), "%Y-%m-%d %H:%M:%S")

                message = MessageChain([
                    Text(f"{nickname}，你好！👋\n欢迎你进入群聊！🎉🎉🎉\n\n我是山田杏奈，这是我的使用帮助:"),
                    Image("code.png"),  # 使用项目目录下的 code.png 作为帮助图
                    Text(f"[加入时间]: {now_time}")
                ])
                await bot.api.post_group_msg(msg["group_id"], rtf=message)
            except Exception as e:
                print(f"❌ 获取用户信息或发送欢迎失败: {e}")

# ===== 程序入口 =====
if __name__ == "__main__":
    bot.run(reload=0)
