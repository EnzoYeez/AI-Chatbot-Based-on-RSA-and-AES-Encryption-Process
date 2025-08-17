# python "C:\Users\Yeez\Desktop\计算机安全\精简\GUI.py"
# ========================== 模块导入 ==========================
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
import base64, os, sys, random, subprocess
import gmpy2

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as padd
import base64
import os



# ========================== 全局变量声明 ==========================
# 这些控件变量将在 init_gui 中初始化并绑定为 global
bit_entry = p_input = q_input = pubkey_input = privkey_input = message_input = encrypt_output = None
cipher_input = decrypt_output = aes_key_entry = aes_plaintext_input = aes_ciphertext_output = None
aes_ciphertext_input = aes_result_output = aes_mode_var = aes_key_size_var = None

rsa_private_key_str = None   # 用于保存本地 RSA 私钥 PEM 字符串
secure_chat_ui = None        # 用于保存 Secure Chat UI 控件引用（由 build_secure_chat_tab 返回）
session_aes_key = None  # 会话 AES 密钥（在解密完成后会保存）
user_public_key_pem = None  # 🟡 建议通过用户ID绑定缓存
session_keys = {}  # 用于缓存每个用户的 AES 会话密钥：user_id -> aes_key（bytes）

# ========================== 图片加密模块 ==========================
def encrypt_image():
    try:
        key = base64.b64decode(aes_key_entry.get())
        filepath = filedialog.askopenfilename(title="选择要加密的图片",
                                              filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")])
        if not filepath:
            return
        with open(filepath, "rb") as f:
            image_data = f.read()

        # 使用GCM模式加密
        nonce = os.urandom(12)
        padder = pad_module.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(image_data) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        tag = encryptor.tag

        # 组合 nonce + tag + ciphertext
        encrypted_data = nonce + tag + ciphertext
        save_path = filedialog.asksaveasfilename(defaultextension=".enc", title="保存加密文件")
        if save_path:
            with open(save_path, "wb") as f:
                f.write(encrypted_data)
            messagebox.showinfo("加密成功", f"图片已加密保存到:\n{save_path}")
    except Exception as e:
        messagebox.showerror("图片加密失败", str(e))


def decrypt_image():
    try:
        key = base64.b64decode(aes_key_entry.get())
        filepath = filedialog.askopenfilename(title="选择加密文件", filetypes=[("Encrypted Files", "*.enc")])
        if not filepath:
            return
        with open(filepath, "rb") as f:
            enc_data = f.read()

        # 分离组件
        nonce = enc_data[:12]
        tag = enc_data[12:28]
        ciphertext = enc_data[28:]

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

        # 去除填充
        unpadder = pad_module.PKCS7(algorithms.AES.block_size).unpadder()
        plain = unpadder.update(padded_plain) + unpadder.finalize()

        save_path = filedialog.asksaveasfilename(defaultextension=".jpg", title="保存解密图片")
        if save_path:
            with open(save_path, "wb") as f:
                f.write(plain)
            messagebox.showinfo("解密成功", f"图片已解密保存到:\n{save_path}")
    except Exception as e:
        messagebox.showerror("图片解密失败", str(e))


# ========================== RSA 功能模块 ==========================
def encrypt_text(original_text, peer_public_key_str):
    public_key = serialization.load_pem_public_key(peer_public_key_str.encode('utf-8'))
    cipher_text = public_key.encrypt(
        original_text.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(cipher_text).decode('utf-8')


def decrypt_text_to_bytes(base64_cipher_text, private_key_str):
    cipher_bytes = base64.b64decode(base64_cipher_text)
    private_key = load_pem_private_key(private_key_str.encode('utf-8'), password=None)
    return private_key.decrypt(
        cipher_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def generate_key_from_pq(p, q):
    try:
        cmd = [sys.executable, "RSA_Tool.py", "-p", str(p), "-q", str(q), "-o", "private.pem"]
        subprocess.run(cmd, check=True)
        with open("private.pem", "rb") as f:
            private_key = load_pem_private_key(f.read(), password=None)
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ).decode()
        os.remove("private.pem")
        return public_pem, private_pem
    except Exception as e:
        raise ValueError(f"密钥生成失败：{e}")


def generate_prime(bits):
    return int(gmpy2.next_prime(random.getrandbits(bits)))


def auto_generate_pq():
    try:
        bits = int(bit_entry.get())
        p, q = generate_prime(bits), generate_prime(bits)
        p_input.delete(0, tk.END); p_input.insert(0, str(p))
        q_input.delete(0, tk.END); q_input.insert(0, str(q))
        messagebox.showinfo("成功", f"已生成 {bits} 位大素数 p 和 q")
    except Exception as e:
        messagebox.showerror("错误", f"生成失败：{e}")


def on_generate_keys():
    try:
        p, q = int(p_input.get()), int(q_input.get())
        pub, priv = generate_key_from_pq(p, q)
        pubkey_input.delete("1.0", tk.END); pubkey_input.insert(tk.END, pub)
        privkey_input.delete("1.0", tk.END); privkey_input.insert(tk.END, priv)
        messagebox.showinfo("密钥生成成功", "RSA 密钥已生成")
    except Exception as e:
        messagebox.showerror("生成失败", str(e))


def on_encrypt():
    pubkey, message = pubkey_input.get("1.0", tk.END).strip(), message_input.get("1.0", tk.END).strip()
    if not pubkey or not message:
        messagebox.showwarning("输入不完整", "请填写公钥和明文")
        return
    try:
        encrypted = encrypt_text(message, pubkey)
        encrypt_output.delete("1.0", tk.END); encrypt_output.insert(tk.END, encrypted)
        messagebox.showinfo("加密成功", "消息已加密")
    except Exception as e:
        messagebox.showerror("加密失败", str(e))


def on_decrypt_to_bytes():
    privkey, cipher = privkey_input.get("1.0", tk.END).strip(), cipher_input.get("1.0", tk.END).strip()
    if not privkey or not cipher:
        messagebox.showwarning("输入不完整", "请填写私钥和密文")
        return
    try:
        decrypted_bytes = decrypt_text_to_bytes(cipher, privkey)
        result = f"解密成功! 数据长度: {len(decrypted_bytes)}字节\n"
        result += f"Base64: {base64.b64encode(decrypted_bytes).decode()}"

        decrypt_output.delete("1.0", tk.END)
        decrypt_output.insert(tk.END, result)
        messagebox.showinfo("解密成功", "消息已解密到二进制")
    except Exception as e:
        messagebox.showerror("解密失败", str(e))


# ========================== AES 功能模块 ==========================
def aes_gcm_encrypt(plaintext: str, key: bytes) -> str:
    """使用AES-GCM模式加密文本"""
    # 将文本编码为字节
    plaintext_bytes = plaintext.encode('utf-8')

    # 添加PKCS7填充
    padder = padd.PKCS7(128).padder()
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


def perform_aes_gcm_encrypt():
    """执行AES-GCM加密操作"""
    try:
        # 获取AES密钥
        key_str = aes_key_entry.get().strip()
        if not key_str:
            messagebox.showwarning("缺少密钥", "请先输入或生成AES密钥")
            return

        key = base64.b64decode(key_str)

        # 获取明文
        plaintext = aes_plaintext_input.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showwarning("缺少明文", "请输入要加密的内容")
            return

        # 使用AES-GCM加密
        encrypted_text = aes_gcm_encrypt(plaintext, key)

        # 显示加密结果
        aes_ciphertext_output.delete("1.0", tk.END)
        aes_ciphertext_output.insert(tk.END, encrypted_text)

        messagebox.showinfo("加密成功", "消息已使用AES-GCM加密")
    except Exception as e:
        messagebox.showerror("加密失败", f"AES-GCM加密失败: {e}")


def aes_decrypt():
    try:
        key = base64.b64decode(aes_key_entry.get())
        ciphertext = aes_ciphertext_input.get("1.0", tk.END).strip()
        if not key or not ciphertext:
            messagebox.showwarning("输入不完整", "请填写AES密钥和密文")
            return

        # 解码并分离组件
        raw = base64.b64decode(ciphertext)
        nonce = raw[:12]
        tag = raw[12:28]  # 16字节的tag
        ct = raw[28:]

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ct) + decryptor.finalize()

        # 去除填充
        unpadder = pad_module.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plain) + unpadder.finalize()

        aes_result_output.delete("1.0", tk.END)
        aes_result_output.insert(tk.END, plaintext.decode())
        messagebox.showinfo("AES解密成功", "密文已解密")
    except Exception as e:
        messagebox.showerror("AES解密失败", str(e))


def generate_aes_key():
    key_size = int(aes_key_size_var.get())
    key = os.urandom(key_size)
    aes_key_entry.delete(0, tk.END)
    aes_key_entry.insert(0, base64.b64encode(key).decode('utf-8'))
    messagebox.showinfo("成功", f"已生成{key_size * 8}位AES密钥")


# ========================== Secure Chat 功能模块 ==========================
# 真实用户开始需要在前端页面上点击ON按钮，代表加密模式开启，然后生成RSA密钥并发给机器人用户公钥，
# 📤 发送纯文本消息（默认行为）
def send_text_message(content: str, user_id: str = "2401262719"):
    """
    真实通过 Napcat API 向指定用户发送私聊文本消息。
    """
    try:
        from ncatbot.core.client import bot
        import asyncio

        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(bot.api.post_private_msg(user_id, text=content))
        else:
            loop.run_until_complete(bot.api.post_private_msg(user_id, text=content))

        print(f"[✅ 已发送文本消息至 {user_id}]: {content}")
    except Exception as e:
        print(f"[❌ 文本消息发送失败]: {e}")

#🔐 发送加密通信结构（Secure Chat 包含 AES 密文 + RSA 密钥）
def send_secure_message(enc_b64: str, encrypted_aes_key_b64: str, user_id: str = "2401262719"):
    import json
    secure_payload = {
        "type": "secure_msg",
        "enc": enc_b64,
        "aes": encrypted_aes_key_b64
    }
    send_text_message(json.dumps(secure_payload), user_id=user_id)

# 🛠️ 发送调试信息（用于开发和调试）
def send_debug_info(tag: str, data: dict, user_id: str = "2401262719"):
    import json
    wrapped = {"type": tag, "data": data}
    send_text_message(json.dumps(wrapped), user_id=user_id)

# 📬 发送消息到机器人（根据消息类型选择发送方式）
def send_message_to_robot(msg: str, msg_type="text", user_id="2401262719"):
    if msg_type == "text":
        send_text_message(msg, user_id)
    elif msg_type == "secure_json":
        send_secure_message(msg["enc"], msg["aes"], user_id)
    else:
        send_debug_info("custom", msg, user_id)

# 启动加密通信会话
def start_encryption_session():
    global rsa_private_key_str, secure_chat_ui

    try:
        from RSA_Encrypt import gen_key
        rsa_public_key, rsa_private_key_str = gen_key()

        # UI 状态更新
        secure_chat_ui["status_label"].config(text="🔐 状态：已开启加密通信", fg="green")
        messagebox.showinfo("加密通信", "已生成RSA密钥，并发送公钥至机器人")

        # 发给机器人的是：特殊启动命令 + 公钥 PEM 字符串
        msg = f"加密通信模式on:{rsa_public_key}"

        # 调用真实发送函数（你应已定义）
        send_text_message(msg, user_id="2401262719")

    except Exception as e:
        messagebox.showerror("启动失败", f"加密通信启动失败：{e}")


# 退出加密通信会话
def stop_encryption_session():
    global rsa_private_key_str, secure_chat_ui

    try:
        # 清除 RSA 私钥（防止误用）
        rsa_private_key_str = None

        # UI 状态更新
        secure_chat_ui["status_label"].config(text="🛑 状态：已退出加密通信", fg="red")
        messagebox.showinfo("加密通信", "已退出加密通信模式，私钥已清除")

        # 发给机器人的是：特殊退出命令（你可以约定内容，例如："加密通信模式off"）
        msg = "加密通信模式off"

        # 调用发送函数（你已定义）
        send_text_message(msg, user_id="2401262719")

    except Exception as e:
        messagebox.showerror("退出失败", f"退出加密通信失败：{e}")


# 接着机器人用户要生成AES密钥，用RSA公钥去加密AES密钥然后发送给真实用户。
import base64
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

def handle_rsa_public_key_message(message: str, user_id="2401262719"):
    """
    机器人端处理来自用户的“开启加密通信”消息，生成 AES 密钥并发送回去。
    """
    try:
        # Step 1: 提取 PEM 公钥字符串
        if "加密通信模式on:" not in message:
            print("[❌ 格式错误]: 非启动加密指令")
            return
        
        rsa_public_key_pem = message.split("加密通信模式on:")[1].strip()
        public_key = serialization.load_pem_public_key(rsa_public_key_pem.encode())

        # Step 2: 随机生成 256-bit AES 密钥
        aes_key = os.urandom(32)  # 32 bytes = 256 bits
        aes_key_b64 = base64.b64encode(aes_key).decode()

        # Step 3: 用 RSA 公钥加密 AES 密钥
        encrypted_key = public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_key_b64 = base64.b64encode(encrypted_key).decode()

        # Step 4: 发回真实用户（格式: JSON 对象）
        secure_payload = {
            "type": "aes_exchange",
            "aes_enc": encrypted_key_b64
        }
        from ncatbot.core.client import bot
        import asyncio, json

        loop = asyncio.get_event_loop()
        msg = json.dumps(secure_payload)

        if loop.is_running():
            asyncio.create_task(bot.api.post_private_msg(user_id, text=msg))
        else:
            loop.run_until_complete(bot.api.post_private_msg(user_id, text=msg))

        print(f"[✅ 已发送 AES 密钥至用户 {user_id}]")

    except Exception as e:
        print(f"[❌ AES 生成或发送失败]: {e}")

# 🔓 接收 AES 密钥并用 RSA 私钥解密
def receive_and_decrypt_aes_key(aes_enc_b64: str):
    global rsa_private_key_str, session_aes_key

    try:
        # 加载私钥对象
        private_key = serialization.load_pem_private_key(
            rsa_private_key_str.encode(), password=None
        )

        # 解密 AES 密钥 (返回二进制)
        encrypted_key = base64.b64decode(aes_enc_b64)
        aes_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        session_aes_key = aes_key  # ✅ 保存二进制AES密钥
        print(f"[✅ 已成功解密并保存 AES 密钥, 长度: {len(aes_key)}字节]")

        # 在UI中显示Base64编码的AES密钥
        aes_key_entry.delete(0, tk.END)
        aes_key_entry.insert(0, base64.b64encode(aes_key).decode('utf-8'))

    except Exception as e:
        print(f"[❌❌ 解密 AES 密钥失败]: {e}")
        messagebox.showerror("解密失败", f"解密AES密钥失败: {e}")


# 🧠 输入明文问题并加密发送
# 在GUI.py中修改
def encrypt_and_send_message_with_aes(plaintext: str, key: bytes, user_id="2401262719"):
    try:
        encrypted_b64 = aes_gcm_encrypt(plaintext, key)

        # 添加调试信息
        print(f"[DEBUG] Encrypted message: {encrypted_b64}")

        # 发送完整的加密数据结构
        secure_json = {
            "type": "secure_msg",
            "enc": encrypted_b64,
            "format": "gcm_base64"  # 明确指定格式
        }
        send_text_message(json.dumps(secure_json), user_id=user_id)
        print("[✅ 已加密消息并发送]")

        # 清空输入框
        secure_chat_ui["user_input"].delete(0, tk.END)
    except Exception as e:
        print(f"[❌❌❌❌ AES 加密发送失败]: {e}")
        messagebox.showerror("发送失败", f"消息发送失败: {e}")



import base64
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pad_module
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
# 假设机器人之前已缓存用户 RSA 公钥（PEM 格式字符串）
def handle_secure_message_from_user(message: str, user_id="2401262719"):
    """
    机器人端：收到用户发来的 secure_msg，解密、生成回答、再加密并发回。
    """
    try:
        # Step 1: 解析消息 JSON
        data = json.loads(message)
        if data.get("type") != "secure_msg":
            print("[⚠️ 非 secure_msg 类型，忽略]")
            return

        ciphertext_b64 = data.get("enc")
        iv_b64 = data.get("iv")

        if not ciphertext_b64 or not iv_b64:
            print("[❌ 缺失字段: enc 或 iv]")
            return

        # Step 2: 取出缓存的 AES 密钥（应已保存在之前 AES exchange 时）
        if user_id not in session_keys:
            print(f"[❌ 未找到用户 {user_id} 的 AES 密钥]")
            return

        aes_key = session_keys[user_id]

        # Step 3: AES 解密明文
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = pad_module.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        user_question = plaintext.decode()

        print(f"[📩 用户消息解密成功]: {user_question}")

        # Step 4: 调用聊天模型生成回答（示例）
        from openai import OpenAI  # 或你自定义的聊天函数
        client = OpenAI()
        history = [{"role": "user", "content": user_question}]
        answer = client.chat.completions.create(model="deepseek-chat", messages=history, max_tokens=3000).choices[0].message.content

        print(f"[🤖 机器人回答]: {answer}")

        # Step 5: 生成新的 AES 密钥并加密回答
        new_aes_key = os.urandom(32)
        new_iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(new_aes_key), modes.CBC(new_iv), backend=default_backend())

        padder = pad_module.PKCS7(128).padder()
        padded_data = padder.update(answer.encode()) + padder.finalize()

        encryptor = cipher.encryptor()
        encrypted_answer = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_answer_b64 = base64.b64encode(encrypted_answer).decode()
        iv_b64 = base64.b64encode(new_iv).decode()

        # Step 6: 加载用户 RSA 公钥
        public_key = serialization.load_pem_public_key(user_public_key_pem.encode())
        encrypted_aes_key = public_key.encrypt(
            new_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode()

        # Step 7: 封装并发送加密回答 + 加密密钥
        secure_payload = {
            "type": "secure_msg",
            "enc": encrypted_answer_b64,
            "iv": iv_b64,
            "aes": encrypted_aes_key_b64
        }

        from ncatbot.core.client import bot
        import asyncio

        loop = asyncio.get_event_loop()
        msg = json.dumps(secure_payload)

        if loop.is_running():
            asyncio.create_task(bot.api.post_private_msg(user_id, text=msg))
        else:
            loop.run_until_complete(bot.api.post_private_msg(user_id, text=msg))

        print(f"[✅ 已发送加密回答至 {user_id}]")

    except Exception as e:
        print(f"[❌ 机器人解密或响应失败]: {e}")







# ========================== 主程序入口 ==========================
def init_gui():
    global bit_entry, p_input, q_input, pubkey_input, privkey_input
    global message_input, encrypt_output, cipher_input, decrypt_output
    global aes_key_entry, aes_plaintext_input, aes_ciphertext_output
    global aes_ciphertext_input, aes_result_output, aes_mode_var, aes_key_size_var

    root = tk.Tk()
    root.title("🔐 RSA/AES 加密解密工具")
    root.geometry("900x1100")

    tab_control = ttk.Notebook(root)

    # RSA Tab
    rsa_tab = ttk.Frame(tab_control)
    tab_control.add(rsa_tab, text='RSA 加密')

    # AES Tab
    aes_tab = ttk.Frame(tab_control)
    tab_control.add(aes_tab, text='AES 加密')

    # Image Tab
    image_tab = ttk.Frame(tab_control)
    tab_control.add(image_tab, text='🖼️ 图片加密')

    # Secure Chat Tab
    secure_tab = ttk.Frame(tab_control)
    tab_control.add(secure_tab, text="💬 Secure Chat")

    tab_control.pack(expand=1, fill="both", padx=10, pady=10)

    # ==== RSA UI ====
    tk.Label(rsa_tab, text="🧮 指定位数生成 p 和 q", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
    bit_frame = tk.Frame(rsa_tab)
    bit_frame.pack(fill="x", padx=10)
    tk.Label(bit_frame, text="位数:").grid(row=0, column=0, sticky="w")
    bit_entry = tk.Entry(bit_frame, width=10)
    bit_entry.insert(0, "1024")
    bit_entry.grid(row=0, column=1)
    tk.Button(bit_frame, text="🎲 自动生成 p 和 q", command=auto_generate_pq, bg="#9C27B0", fg="white").grid(row=0, column=2, padx=10)

    pq_frame = tk.Frame(rsa_tab)
    pq_frame.pack(fill="x", padx=10, pady=(5, 5))
    tk.Label(pq_frame, text="p:").grid(row=0, column=0)
    p_input = tk.Entry(pq_frame, width=70)
    p_input.grid(row=0, column=1)
    tk.Label(pq_frame, text="q:").grid(row=1, column=0)
    q_input = tk.Entry(pq_frame, width=70)
    q_input.grid(row=1, column=1)
    tk.Button(pq_frame, text="🔧 根据 p 和 q 生成密钥", command=on_generate_keys, bg="#FF9800", fg="white").grid(row=0, column=2, rowspan=2, padx=10)

    tk.Label(rsa_tab, text="🔐 RSA 加密部分", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(20, 5))
    tk.Label(rsa_tab, text="📌 公钥 (PEM)").pack(anchor="w", padx=10)
    pubkey_input = scrolledtext.ScrolledText(rsa_tab, height=6)
    pubkey_input.pack(fill="x", padx=10)

    tk.Label(rsa_tab, text="✉️ 明文").pack(anchor="w", padx=10)
    message_input = scrolledtext.ScrolledText(rsa_tab, height=3)
    message_input.pack(fill="x", padx=10)
    tk.Button(rsa_tab, text="🔐 加密消息", command=on_encrypt, bg="#4CAF50", fg="white").pack(pady=5)

    tk.Label(rsa_tab, text="📤 密文（Base64）").pack(anchor="w", padx=10)
    encrypt_output = scrolledtext.ScrolledText(rsa_tab, height=3)
    encrypt_output.pack(fill="x", padx=10, pady=(0, 20))

    tk.Label(rsa_tab, text="🔓 RSA 解密部分", font=("Arial", 12, "bold")).pack(anchor="w", padx=10)
    tk.Label(rsa_tab, text="🔑 私钥 (PEM)").pack(anchor="w", padx=10)
    privkey_input = scrolledtext.ScrolledText(rsa_tab, height=6)
    privkey_input.pack(fill="x", padx=10)
    tk.Label(rsa_tab, text="📥 密文（Base64）").pack(anchor="w", padx=10)
    cipher_input = scrolledtext.ScrolledText(rsa_tab, height=3)
    cipher_input.pack(fill="x", padx=10)
    tk.Button(rsa_tab, text="🔓 解密密文", command=on_decrypt_to_bytes, bg="#2196F3", fg="white").pack(pady=5)
    tk.Label(rsa_tab, text="📄 明文结果").pack(anchor="w", padx=10)
    decrypt_output = scrolledtext.ScrolledText(rsa_tab, height=3)
    decrypt_output.pack(fill="x", padx=10, pady=(0, 20))
    tk.Button(rsa_tab, text="🔓🔓 解密到二进制", command=on_decrypt_to_bytes, bg="#2196F3", fg="white").pack(pady=5)

    # ==== AES UI ====
    tk.Label(aes_tab, text="🔑 AES 密钥设置", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
    key_frame = tk.Frame(aes_tab)
    key_frame.pack(fill="x", padx=10)
    tk.Label(key_frame, text="密钥长度:").grid(row=0, column=0)
    aes_key_size_var = tk.StringVar(value="32")
    ttk.Combobox(key_frame, textvariable=aes_key_size_var, values=("16", "24", "32"), width=10, state="readonly").grid(row=0, column=1)
    tk.Label(key_frame, text="密钥(Base64):").grid(row=1, column=0, pady=(5, 0))
    aes_key_entry = tk.Entry(key_frame, width=70)
    aes_key_entry.grid(row=1, column=1, columnspan=3, sticky="we", pady=(5, 0))
    tk.Button(key_frame, text="🎲 生成随机密钥", command=generate_aes_key, bg="#9C27B0", fg="white").grid(row=0, column=4, rowspan=2, padx=10)

    tk.Label(aes_tab, text="🔐 AES 加密", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(20, 5))
    tk.Label(aes_tab, text="✉️ 明文").pack(anchor="w", padx=10)
    aes_plaintext_input = scrolledtext.ScrolledText(aes_tab, height=20)
    aes_plaintext_input.pack(fill="x", padx=10)
    tk.Button(aes_tab, text="🔐 加密消息", command=perform_aes_gcm_encrypt, bg="#4CAF50", fg="white").pack(pady=5)
    tk.Label(aes_tab, text="📤 密文（Base64）").pack(anchor="w", padx=10)
    aes_ciphertext_output = scrolledtext.ScrolledText(aes_tab, height=5)
    aes_ciphertext_output.pack(fill="x", padx=10, pady=(0, 20))

    tk.Label(aes_tab, text="🔓 AES 解密", font=("Arial", 12, "bold")).pack(anchor="w", padx=10)
    tk.Label(aes_tab, text="📥 密文（Base64）").pack(anchor="w", padx=10)
    aes_ciphertext_input = scrolledtext.ScrolledText(aes_tab, height=5)
    aes_ciphertext_input.pack(fill="x", padx=10)
    tk.Button(aes_tab, text="🔓 解密密文", command=aes_decrypt, bg="#2196F3", fg="white").pack(pady=5)
    tk.Label(aes_tab, text="📄 解密结果").pack(anchor="w", padx=10)
    aes_result_output = scrolledtext.ScrolledText(aes_tab, height=20)
    aes_result_output.pack(fill="x", padx=10, pady=(0, 20))

    # ==== Image UI ====
    tk.Label(image_tab, text="📷 图片加密与解密", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
    tk.Label(image_tab, text="✅ 使用 AES（同步当前设置）").pack(anchor="w", padx=10)
    tk.Button(image_tab, text="🖼️ 加密图片文件", command=encrypt_image, bg="#4CAF50", fg="white").pack(padx=10, pady=10)
    tk.Button(image_tab, text="🖼️ 解密为图片", command=decrypt_image, bg="#2196F3", fg="white").pack(padx=10, pady=(0, 20))

    # ==== Secure Chat UI ====
    # 状态栏
    status_label = tk.Label(secure_tab, text="🔒🔒 状态：未开启加密通信", fg="red", font=("Arial", 10, "bold"))
    status_label.pack(anchor="w", padx=10, pady=(10, 5))

    # 接收区
    tk.Label(secure_tab, text="📥📥 收到消息（明文）").pack(anchor="w", padx=10)
    received_text = scrolledtext.ScrolledText(secure_tab, height=10, state="disabled", wrap=tk.WORD)
    received_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    # 输入区
    tk.Label(secure_tab, text="✏✏️ 输入明文").pack(anchor="w", padx=10)
    user_input = tk.Entry(secure_tab)
    user_input.pack(fill="x", padx=10, pady=(0, 10))

    # 操作按钮
    button_frame = tk.Frame(secure_tab)
    button_frame.pack(pady=(0, 10))

    # 在创建发送按钮的地方，修改为：
    send_btn = tk.Button(button_frame, text="📤📤📤📤 发送", width=10,
                         command=lambda: encrypt_and_send_message_with_aes(
                             plaintext=secure_chat_ui["user_input"].get(),
                             key=session_aes_key
                         ))
    send_btn.grid(row=0, column=0, padx=5)

    start_btn = tk.Button(button_frame, text="🔑🔑 开启加密通信", width=16, command=start_encryption_session)
    start_btn.grid(row=0, column=1, padx=5)

    stop_btn = tk.Button(button_frame, text="❌❌ 退出加密通信", width=16, command=stop_encryption_session)
    stop_btn.grid(row=0, column=2, padx=5)

    # 新增：AES密钥交换部分
    aes_key_frame = tk.Frame(secure_tab)
    aes_key_frame.pack(fill="x", padx=10, pady=10)

    tk.Label(aes_key_frame, text="🔑🔑 加密的AES密钥(Base64):").pack(anchor="w")
    encrypted_aes_entry = tk.Entry(aes_key_frame, width=80)
    encrypted_aes_entry.pack(fill="x", pady=5)

    def handle_set_aes_key():
        encrypted_aes_b64 = encrypted_aes_entry.get().strip()
        if encrypted_aes_b64:
            receive_and_decrypt_aes_key(encrypted_aes_b64)

    set_aes_btn = tk.Button(aes_key_frame, text="🔓 解密并设置AES密钥", command=handle_set_aes_key)
    set_aes_btn.pack(pady=5)

    # 👇👇 将这些组件绑定为全局变量
    global secure_chat_ui
    secure_chat_ui = {
        "status_label": status_label,
        "received_text": received_text,
        "user_input": user_input,
        "send_btn": send_btn,
        "start_btn": start_btn,
        "stop_btn": stop_btn,
        "encrypted_aes_entry": encrypted_aes_entry
    }


    root.mainloop()


if __name__ == '__main__':
    init_gui()
