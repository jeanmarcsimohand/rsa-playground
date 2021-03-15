import multiprocessing
import random
import math
from binascii import hexlify, unhexlify
from typing import Union


class Rsa:
    PKCS7_PADDING = 7
    NULL_PADDING = 1

    def __init__(self, bits: int = 2 ** 64, public_exponent: int = 65537):
        self.modulus = 0
        self.bits = bits
        self.d = 0
        self.p = 0
        self.q = 0
        self.exponent = public_exponent

    @staticmethod
    def _lcm(n1: int, n2: int) -> int:
        return int(abs(n1 * n2) // math.gcd(n1, n2))

    @staticmethod
    def _miller_rabin_prime_test(n: int, k: int = 10) -> bool:
        """
        check if n is a prime number

        implementation based on Miller variant test
        https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

        :param n: number to test
        :param k: number of round for checking
        :return: True if prime, otherwise returns False
        """

        if n <= 3:
            if n == 1 or n == 0:
                return False
            return True

        # write n as 2^(r)·d + 1 with d odd (by factoring out powers of 2 from n − 1)
        # 2^(r) * d = n - 1
        # start with r = 0, then d = n -1
        r, d = 0, n - 1

        # now ensure d is odd
        while 0 == d & 1:
            # r is exponentiation of 2, increasing r by 1 implies to divide d by 2
            r, d = r + 1, d >> 1

        assert 2 ** r * d == n - 1 and d & 1

        # here d is odd and n - 1 = 2^(r) * d

        for loop in range(k):
            # pick a random integer 'a' in the range [2, n − 2]
            # then x is a^d mod n
            x = pow(random.randrange(2, n - 1), d, n)

            if x == 1 or x == n - 1:
                # pick another one
                continue

            for inner in range(1, r - 1):
                # compute x² mod n
                y = pow(x, 2, n)
                if y == 1:
                    print("nope, it has it is a multiple of {}".format(str(math.gcd(x - 1, n))))
                    return False  # multiple of GCD (x - 1,n)

                x = y
                if x == n - 1:
                    # stop inner loop, continue outer loop
                    break
            else:
                return False  # Composite
        return True  # probably prime

    def _get_prime(self, k: int = 30, result: dict = None) -> dict:
        """
        Generate a prime number with length of 'bits' and perform k round of verification
        :param result: multiprocessing shared variable
        :param k: number of verification round
        :return: the prime number
        """
        while True:
            # pick a random number in 2^(bits - 1) and 2^(bits) - 1
            n = random.randrange(pow(2, self.bits - 1), pow(2, self.bits))
            if 0 == n & 1:
                continue

            if self._miller_rabin_prime_test(n, k):
                result.update({'prime': n})
                return result

    @staticmethod
    def _modular_inverse(a: int, n: int):
        """
        Compute the modular inverse thanks to the Extended Euclidean algorithm
        https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
        :param a: value to inverse
        :param n: modulus
        :return: the modular inverse or raise a ValueError exception
        """

        t, new_t = 0, 1
        r, new_r = n, a

        while new_r != 0:
            quotient = r // new_r
            t, new_t = new_t, t - quotient * new_t
            r, new_r = new_r, r - quotient * new_r

        if r > 1:
            raise ValueError("a is not invertible")
        if t < 0:
            t = t + n

        return t

    def _pkcs7_pad(self, message: Union[str, bytes]) -> bytes:
        """
        Pads input buffer using PKCS #7 padding scheme
        please refer to https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
        :param message: bytes or string buffer to pad
        :return: padded buffer as bytes-buffer
        """
        block_size = int(self.bits // 8)
        blocks = math.ceil(len(message) / block_size)
        pad_value = int(blocks * block_size - len(message))

        if block_size > 256:
            raise ValueError("PKCS#7 padding is valid only for block length lesser than 256 bytes")

        if pad_value == 0:
            pad_value = block_size

        if isinstance(message, str):
            return message.encode() + int.to_bytes(pad_value % 256, 1, 'little') * pad_value
        elif isinstance(message, bytes):
            return message + int.to_bytes(pad_value % 256, 1, 'little') * pad_value
        else:
            raise TypeError("Message must be a string or a byte-like buffer")

    def _null_pad(self, message: Union[str, bytes]) -> bytes:
        """
        Pads the PKCS #1 v1.5 padding scheme
        :param message: bytes or string buffer to pad
        :return: padded buffer as bytes-buffer
        """
        block_size = int(self.bits // 8)
        blocks = math.ceil(len(message) / block_size)
        pad_length = int(blocks * block_size - len(message))

        if isinstance(message, bytes):
            return message + b'\x00' * pad_length
        elif isinstance(message, str):
            return (message + '\x00' * pad_length).encode()
        else:
            raise TypeError("Message must be a string or a byte-like buffer")

    def _pkcs7_unpad(self, message: bytes) -> bytes:
        """
        remove PKCS #7 padding from the input buffer
        please refer to https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
        :param message: bytes or string buffer
        :return: 'un-padded' buffer as bytes-buffer
        """

        block_size = int(self.bits // 8)

        if isinstance(message, bytes) is False:
            raise TypeError("Invalid message type, expecting byte-like buffer")

        if block_size > 256:
            raise ValueError("PKCS#7 padding is valid only for block length lesser than 256 bytes")

        if len(message) % block_size != 0:
            raise ValueError("message is not padded ?")

        if message[-1] > block_size:
            raise ValueError("Invalid padding value")

        if message[-1] != 0:
            pad_value = -message[-1]
        else:
            # if padding is 0, this is a null block
            # it comes after a non padded block
            pad_value = -block_size

        return message[:pad_value]

    def _null_unpad(self, message: bytes) -> bytes:
        """
        Remove the PKCS #1 v1.5 padding from the input buffer
        :param message: bytes or string buffer to pad
        :return: 'un-padded' buffer as bytes-buffer
        """
        if isinstance(message, bytes) is False:
            raise TypeError("Invalid message type, expecting byte-like buffer")

        if len(message) % int(self.bits // 8) != 0:
            raise ValueError("message is not padded ?")

        return message.rstrip(b'\x00')

    def keygen(self):
        """
        Generates n, e, d (modulus, public exponent, private exponent)
        :return: None
        """
        # based on https://en.wikipedia.org/wiki/RSA_(cryptosystem)

        # Note: as we have to generate 2 big prime numbers,
        #       and today's computers have many cores,
        #       we will run 2 processes (not thread!)
        manager = multiprocessing.Manager()
        result_p = manager.dict()
        result_q = manager.dict()
        p_thread = multiprocessing.Process(target=self._get_prime, kwargs={"k": 30, "result": result_p})
        q_thread = multiprocessing.Process(target=self._get_prime, kwargs={"k": 30, "result": result_q})
        p_thread.start()
        q_thread.start()
        p_thread.join()
        q_thread.join()
        q = result_q['prime']
        p = result_p['prime']
        self.modulus = p * q  # this is the modulus for public key

        lambda_n = self._lcm(p - 1, q - 1)

        if self.exponent < 1 or self.exponent >= lambda_n:
            self.exponent = 2

        while math.gcd(self.exponent, lambda_n) != 1:
            # instead of returning an error, I search for the next
            # valid public exponent
            self.exponent += 1
            print("Trying with next exponent {}".format(str(self.exponent)))
            if self.exponent >= lambda_n:
                raise ValueError("Unable to find a matching exponent")

        # compute d, the modular multiplication inverse (aka our private exponent)
        self.d = self._modular_inverse(self.exponent, lambda_n)

    def get_pubkey(self):
        """
        :return: the modulus and the public exponent
        """
        return self.modulus, self.exponent

    def get_privkey(self):
        """
        ABSOLUTELY NON-SECURE :-)
        :return: the modulus and the private exponent
        """
        return self.modulus, self.d

    def encrypt(self, message: Union[bytes, str], padding: Union[int, None] = PKCS7_PADDING) -> bytes:
        """
        Encrypt the message using our public exponent and modulus (class members)
        Note: if padding is None, the input message must be one the block length
        :param message: string message
        :param padding: either PKCS7_PADDING, NULL_PADDING, or None
        :return: ciphered message
        """
        result = []
        block_size = int(self.bits // 8)
        # format the output as hex string (each byte is encoded in 2 hex digits)
        block_format = '{{cipher:{hexlength:04d}X}}'.format(hexlength=block_size * 2)

        # first pad the input buffer to reach the block_size
        if padding == self.PKCS7_PADDING:
            message = self._pkcs7_pad(message)
        elif padding == self.NULL_PADDING:
            message = self._null_pad(message)
        else:
            if len(message) != block_size:
                raise ValueError("Invalid message length (must be {} bytes length".format(str(block_size)))
            if isinstance(message, str):
                message = message.encode()
            elif isinstance(message, bytes) is False:
                raise TypeError("Invalid message: must be string or bytes")

        # for each block do:
        for start in range(0, len(message), block_size):
            # get message blocks of 'block_size' length
            message_block = message[start: start + block_size]

            # convert byte buffer to big int
            plaintext_block = int(hexlify(message_block), 16)

            # process encryption: c = m^e mod n
            # where    m: plaintext message block,
            #          c: ciphered message block
            #          e: public exponent
            #          n: modulus
            ciphered_block = pow(plaintext_block, self.exponent, self.modulus)

            # Format the output as 'block_size' length buffer
            ciphered_block = block_format.format(cipher=ciphered_block).encode()
            if len(ciphered_block) & 1:
                ciphered_block = b'0' + ciphered_block

            result.append(unhexlify(ciphered_block))

        # return the concatenation of each ciphered blocks
        return b''.join(result)

    def decrypt(self, message: bytes, padding: Union[int, None] = PKCS7_PADDING) -> bytes:
        block_size = int(self.bits // 8)
        plaintext_blocks = []
        # use a formatter to store 2*n hex digits (n=block_size)
        block_format = '{{cipher:{hexlength:04d}X}}'.format(hexlength=block_size * 2)

        # for each block do:
        # note that we use block_size*2 as we expect the input to be
        # a Hex string, where 2 hex digits represent 1 byte
        for start in range(0, len(message), block_size*2):
            # get the current ciphered block
            ciphered_block = message[start: start + block_size * 2]

            # convert it to big numbers
            ciphered_int_block = int(hexlify(ciphered_block), 16)

            # decrypt the message with :  m = c^d mod n
            # where    m: plaintext message block,
            #          c: ciphered message block
            #          d: private exponent
            #          n: modulus
            clear_block = pow(ciphered_int_block, self.d, self.modulus)

            # Format the output as 'block_size' length buffer
            clear_block = block_format.format(cipher=clear_block).encode()
            if len(clear_block) & 1:
                clear_block = b'0' + clear_block

            plaintext_blocks.append(unhexlify(clear_block))

        # then concatenate each plaintext blocks to re-build the message
        result = b''.join(plaintext_blocks)

        # and finally remove the padding
        if padding == self.PKCS7_PADDING:
            return self._pkcs7_unpad(result)
        elif padding == self.NULL_PADDING:
            return self._null_unpad(result)
        else:
            return result


if __name__ == "__main__":
    rsa = Rsa(public_exponent=65537, bits=1024)
    rsa.keygen()

    modulus, exponent = rsa.get_pubkey()
    _, priv = rsa.get_privkey()

    print("Public Exponent {}".format(hex(exponent).upper()[2:]))
    print("Pub modulus {}".format(hex(modulus).upper()[2:]))
    print("Private Exponent: {}".format(hex(priv).upper()[2:]))
    print("Block size: {} bytes".format(str(int(rsa.bits//8))))

    test_text = b"abcdefghijklmnopqrstuvwxyz123456-abcdefghijklmnopqrstuvwxyz12345" +\
                b"abcdefghijklmnopqrstuvwxyz123456-abcdefghijklmnopqrstuvwxyz12345" +\
                b"abcdefghijklmnopqrstuvwxyz123456-abcdefghijklmnopqrstuvwxyz12345"

    ciphered = rsa.encrypt(message=test_text, padding=rsa.NULL_PADDING)
    print("Ciphered", hexlify(ciphered).decode().upper())
    plaintext = rsa.decrypt(message=ciphered, padding=rsa.NULL_PADDING)

    print("Plaintext", plaintext)

    if isinstance(test_text, str):
        plaintext = plaintext.decode()

    if test_text != plaintext:
        print("Error: decrypted message does not match with original text")
