# ====================== 标准库导入 ======================
import os
import sys
import subprocess
import random
import base64

# ====================== 第三方库导入 ======================
import gmpy2
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature

# ====================== 自定义模块导入 ======================
from RSA_Tool import RSA


# ============================================================
# 👑 Part 1: RSA 密钥生成相关函数
# ============================================================

def generate_large_prime(bits=1024):
    """生成指定位数的大素数"""
    return gmpy2.next_prime(random.getrandbits(bits))


def gen_p_q():
    """生成两个大素数 p 和 q"""
    p = generate_large_prime(1024)
    q = generate_large_prime(1024)
    return p, q


def gen_key():
    """
    生成 RSA 密钥对，并返回公钥和私钥的 PEM 编码字符串（utf-8编码）
    使用 RSA_Tool.py 进行 PEM 格式生成
    """
    p, q = gen_p_q()

    # 构造命令参数
    params = {
        '-p': p,
        '-q': q,
        '-o': "private.pem"
    }
    cmd = [sys.executable, "RSA_Tool.py"]
    for key, value in params.items():
        cmd.append(str(key))
        cmd.append(str(value))

    # 执行命令生成 PEM 文件
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stderr:
        print("⚠️ 错误信息:", result.stderr)

    # 加载私钥
    with open("private.pem", "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    # 提取并编码公钥
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_str = public_pem.decode('utf-8')

    # 编码私钥
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_str = private_pem.decode('utf-8')

    # 清理临时文件
    if os.path.exists("private.pem"):
        os.remove("private.pem")
    if os.path.exists("public.pem"):
        os.remove("public.pem")

    return public_key_str, private_key_str


# ============================================================
# 🔐 Part 2: 加密 / 解密函数
# ============================================================

def encrypt_text(original_text: str, peer_public_key_str: str) -> str:
    """
    使用对方的公钥加密明文字符串，返回 Base64 编码的结果
    """
    try:
        data = original_text.encode('utf-8')

        # 校验 PEM 格式
        if not peer_public_key_str.strip().startswith("-----BEGIN PUBLIC KEY-----"):
            raise ValueError("公钥格式不正确，缺少 PEM 头部")
        if not peer_public_key_str.strip().endswith("-----END PUBLIC KEY-----"):
            raise ValueError("公钥格式不正确，缺少 PEM 尾部")

        # 加载公钥
        public_key = serialization.load_pem_public_key(
            peer_public_key_str.encode('utf-8')
        )

        # 执行加密
        cipher_text = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(cipher_text).decode('utf-8')

    except Exception as e:
        raise ValueError(f"Encryption failed: {e}") from e


def decrypt_text(encrypted_base64: str, my_private_key_str: str) -> str:
    """
    使用自己的私钥解密 Base64 编码的密文，返回原始文本
    """
    cipher_text = base64.b64decode(encrypted_base64)

    private_key = serialization.load_pem_private_key(
        my_private_key_str.encode('utf-8'),
        password=None
    )

    plain_bytes = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plain_bytes.decode('utf-8')


# ============================================================
# 🧪 Part 3: 测试入口（仅在直接运行时触发）
# ============================================================

if __name__ == "__main__":
    print("🔄 正在生成 RSA 密钥对...")
    peer_pub, my_priv = gen_key()
    print("✅ 密钥对生成完成。\n")

    message = "这是一条需要加密并安全传输的秘密信息！Hello RSA Encryption! 🚀"
    print("🔓 明文消息：", message)

    encrypted_b64 = encrypt_text(message, peer_pub)
    print("\n🔐 加密后 (Base64):")
    print(encrypted_b64[:100] + "...（截断显示）")

    decrypted = decrypt_text(encrypted_b64, my_priv)
    print("\n🔓 解密后消息：", decrypted)

    if message == decrypted:
        print("\n✅ 加密/解密测试成功！")
    else:
        print("\n❌ 测试失败：原始文本与解密文本不一致！")
