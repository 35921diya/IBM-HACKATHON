from flask import Flask, render_template, request
import time, hashlib, struct, base64, os

app = Flask(__name__)

TIME_STEP = 30     # seconds
DIGITS = 6         # OTP digits


def generate_secret():
    return base64.b32encode(os.urandom(10)).decode("utf-8").replace("=", "")


def hmac_sha1(key, msg):
    block_size = 64
    if len(key) > block_size:
        key = hashlib.sha1(key).digest()
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))

    o_key_pad = bytes((b ^ 0x5c) for b in key)
    i_key_pad = bytes((b ^ 0x36) for b in key)

    inner = hashlib.sha1(i_key_pad + msg).digest()
    return hashlib.sha1(o_key_pad + inner).digest()


def generate_otp(secret, for_time=None):
    if for_time is None:
        for_time = int(time.time())
    counter = int(for_time // TIME_STEP)

    key = base64.b32decode(secret + "=" * (8 - len(secret) % 8))
    msg = struct.pack(">Q", counter)

    hmac_val = hmac_sha1(key, msg)
    offset = hmac_val[-1] & 0x0F
    code = struct.unpack(">I", hmac_val[offset:offset+4])[0] & 0x7FFFFFFF

    otp = str(code % (10 ** DIGITS)).zfill(DIGITS)
    return otp


def validate_otp(secret, otp):
    now = int(time.time())
    for w in [-1, 0, 1]:  # accept 1 step clock drift
        t = now + w * TIME_STEP
        if generate_otp(secret, t) == otp:
            return True
    return False


@app.route("/", methods=["GET", "POST"])
def home():
    secret = generate_secret()
    otp = generate_otp(secret)
    expire = TIME_STEP - (int(time.time()) % TIME_STEP)

    message = ""
    result_color = ""

    if request.method == "POST":
        user_otp = request.form.get("otp")
        input_secret = request.form.get("secret")

        if validate_otp(input_secret, user_otp):
            message = "✅ OTP is Valid!"
            result_color = "green"
        else:
            message = "❌ Invalid OTP!"
            result_color = "red"

        secret = input_secret
        otp = generate_otp(secret)
        expire = TIME_STEP - (int(time.time()) % TIME_STEP)

    return render_template("index.html",
                           secret=secret,
                           otp=otp,
                           expire=expire,
                           message=message,
                           result_color=result_color)


if __name__ == "__main__":
    app.run(debug=True)
