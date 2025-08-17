# ===== 标准库导入 =====
import sys
import base64
import random
import argparse
import textwrap

# ===== 第三方库 =====
import gmpy2
from pyasn1.codec.der import encoder
from pyasn1.type.univ import Sequence, Integer


# ===== 常量定义 =====
PEM_TEMPLATE = (
    '-----BEGIN RSA PRIVATE KEY-----\n'
    '%s\n'
    '-----END RSA PRIVATE KEY-----\n'
)

DEFAULT_EXP = 65537


# ===== 辅助函数 =====
def factor_modulus(n, d, e):
    """
    使用 d, e, n 还原出非平凡因子 (p, q)
    来源：《Handbook of Applied Cryptography》第8章
    """
    t = e * d - 1
    s = 0

    if d <= 1 or e <= 1:
        raise ValueError("d, e can't be <=1")

    if 17 != gmpy2.powmod(17, e * d, n):
        raise ValueError("n, d, e don't match")

    while True:
        t, remainder = divmod(t, 2)
        if remainder:
            break
        s += 1

    found = False
    tries = 0
    while not found:
        tries += 1
        if tries >= 1000:
            raise ValueError("Factorization/d: no success after 1000 tries")
        a = random.randint(1, n - 1)
        i = 1
        while i <= s and not found:
            c1 = pow(a, pow(2, i - 1, n) * t, n)
            c2 = pow(a, pow(2, i, n) * t, n)
            found = c1 != 1 and c1 != (-1 % n) and c2 == 1
            i += 1

    p = gmpy2.gcd(c1 - 1, n)
    q = n // p
    return p, q


def factor_dp(n, dp, e):
    """
    使用 dp 求解 (p, q)
    来源：https://eprint.iacr.org/2020/1506.pdf 第9页算法
    """
    p = 1
    v = 2
    while p == 1:
        a = gmpy2.mpz(v)
        t = gmpy2.powmod(a, e * dp - 1, n) - 1
        p = gmpy2.gcd(t, n)
        v += 1
        if v > 100:
            raise ValueError("Factorization/dp: no success after 100 tries")
    q = n // p
    if p * q != n:
        raise ValueError("Factorization with dp failed")
    return p, q


# ===== 主类定义 =====
class RSA:
    def __init__(self, p=None, q=None, n=None, d=None, dp=None, e=DEFAULT_EXP):
        """
        用 (p, q) 或 (n, d) 或 (n, dp) 初始化 RSA 参数
        """
        self.e = e

        if p and q:
            assert gmpy2.is_prime(p), 'p is not prime'
            assert gmpy2.is_prime(q), 'q is not prime'
            self.p = p
            self.q = q
        elif n and d:
            self.p, self.q = factor_modulus(n, d, e)
        elif n and dp:
            self.p, self.q = factor_dp(n, dp, e)
        else:
            raise ValueError('Either (p, q) or (n, d) must be provided')

        self._calc_values()

    def _calc_values(self):
        self.n = self.p * self.q
        phi = (self.p - 1) * (self.q - 1) if self.p != self.q else (self.p ** 2) - self.p
        self.d = gmpy2.invert(self.e, phi)
        self.dP = self.d % (self.p - 1)
        self.dQ = self.d % (self.q - 1)
        self.qInv = gmpy2.invert(self.q, self.p)

    def to_pem(self):
        b64 = base64.b64encode(self.to_der()).decode()
        b64w = "\n".join(textwrap.wrap(b64, 64))
        return (PEM_TEMPLATE % b64w).encode()

    def to_der(self):
        seq = Sequence()
        for idx, x in enumerate([0, self.n, self.e, self.d, self.p, self.q, self.dP, self.dQ, self.qInv]):
            seq.setComponentByPosition(idx, Integer(x))
        return encoder.encode(seq)

    def dump(self, verbose):
        vars = ['n', 'e', 'd', 'p', 'q']
        if verbose:
            vars += ['dP', 'dQ', 'qInv']
        for v in vars:
            self._dumpvar(v)

    def _dumpvar(self, var):
        val = getattr(self, var)

        def parts(s, n):
            return '\n'.join([s[i:i + n] for i in range(0, len(s), n)])

        if len(str(val)) <= 40:
            print('%s = %d (%#x)\n' % (var, val, val))
        else:
            print('%s =' % var)
            print(parts('%x' % val, 80) + '\n')


# ===== 命令行入口 =====
if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-n', type=lambda x: int(x, 0), help='modulus. format : int or 0xhex')
    parser.add_argument('-p', type=lambda x: int(x, 0), help='first prime number. format : int or 0xhex')
    parser.add_argument('-q', type=lambda x: int(x, 0), help='second prime number. format : int or 0xhex')
    parser.add_argument('-d', type=lambda x: int(x, 0), help='private exponent. format : int or 0xhex')
    parser.add_argument('-e', type=lambda x: int(x, 0), default=DEFAULT_EXP,
                        help=f'public exponent (default: {DEFAULT_EXP}). format : int or 0xhex')
    parser.add_argument('--dp', type=lambda x: int(x, 0), help='d (mod p-1) or d (mod q-1) : int or 0xhex')
    parser.add_argument('-o', '--output', help='output filename')
    parser.add_argument('-f', '--format', choices=['DER', 'PEM'], default='PEM',
                        help='output format (DER, PEM) (default: PEM)')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='also display CRT-RSA representation')

    args = parser.parse_args()

    # 构造 RSA 对象
    if args.p and args.q:
        print('Using (p, q) to calculate RSA paramaters\n')
        rsa = RSA(p=args.p, q=args.q, e=args.e)
    elif args.n and args.d:
        print('Using (n, d) to calculate RSA parameters\n')
        rsa = RSA(n=args.n, d=args.d, e=args.e)
    elif args.n and args.dp:
        print('Using (n, dp) to calculate RSA parameters\n')
        rsa = RSA(n=args.n, dp=args.dp, e=args.e)
    else:
        parser.print_help()
        parser.error('Either (p, q), (n, d) or (n, dp) needs to be specified')

    if args.format == 'DER' and not args.output:
        parser.error('Output filename (-o) required for DER output')

    rsa.dump(args.verbose)

    if args.format == 'PEM':
        data = rsa.to_pem()
    elif args.format == 'DER':
        data = rsa.to_der()

    if args.output:
        print(f'Saving {args.format} as {args.output}')
        with open(args.output, 'wb') as fp:
            fp.write(data)
    else:
        sys.stdout.buffer.write(data)
