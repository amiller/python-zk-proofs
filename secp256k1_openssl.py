import ctypes
import ctypes.util
import struct

def uint256_from_str(s):
    """Convert bytes to uint256"""
    r = 0
    t = struct.unpack(b"<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r

def uint256_to_str(s):
    """Convert bytes to uint256"""
    assert 0 <= s < 2**256
    t = []
    for i in range(8):
        t.append((s >> (i * 32) & 0xffffffff))
    s = struct.pack(b"<IIIIIIII", *t)
    return s

_ssl = ctypes.cdll.LoadLibrary(ctypes.util.find_library('ssl') or 'libeay32')
_ssl.BN_bn2hex.restype = ctypes.c_char_p
# this specifies the curve used with ECDSA.
_NID_secp256k1 = 714 # from openssl/obj_mac.h

# test that openssl support secp256k1
if _ssl.EC_KEY_new_by_curve_name(_NID_secp256k1) == 0:
    errno = _ssl.ERR_get_error()
    errmsg = ctypes.create_string_buffer(120)
    _ssl.ERR_error_string_n(errno, errmsg, 120)
    raise RuntimeError('openssl error: %s' % errmsg.value)


# Thx to Sam Devlin for the ctypes magic 64-bit fix.
def _check_result (val, func, args):
    if val == 0:
        raise ValueError
    else:
        return ctypes.c_void_p(val)

_ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
_ssl.EC_KEY_new_by_curve_name.errcheck = _check_result

curve = _ssl.EC_KEY_new_by_curve_name(_NID_secp256k1)
group = _ssl.EC_KEY_get0_group(curve)
order = _ssl.BN_new()
_ctx = _ssl.BN_CTX_new()
_ssl.EC_GROUP_get_order(group, order, _ctx)

class SPoint(object):
    _fields_ = [('point',int)]

    def __init__(self, x=None, y=None, ybit=None, _point=None):
        assert x is None or type(x) is long
        assert ybit is None or type(ybit) is int
        if x is None:
            assert y is None
            assert _point is not None
            self.point = _point
            return
        else:
            assert y is not None or ybit is not None
            assert _point is None

        self.point = _ssl.EC_POINT_new(group)
        ctx = _ssl.BN_CTX_new()
        x = _ssl.BN_bin2bn(uint256_to_str(x)[::-1], 32, _ssl.BN_new())
        
        if y is not None:
            y = _ssl.BN_bin2bn(uint256_to_str(y)[::-1], 32, _ssl.BN_new())
            _ssl.EC_POINT_set_affine_coordinates_GFp(group, self.point, x, y, ctx)
        else:
            _ssl.EC_POINT_set_compressed_coordinates_GFp(group, self.point, x, y%2, ctx)

        _check = _ssl.EC_POINT_is_on_curve(group, self.point, ctx)
        assert _check

        _ssl.BN_CTX_free(ctx)

    def _coords(self):
        ctx = _ssl.BN_CTX_new()
        x = _ssl.BN_new()
        y = _ssl.BN_new()
        _ssl.EC_POINT_get_affine_coordinates_GFp(group, self.point, x, y, ctx)
        def _bn2bin(bn):
            buf = ctypes.create_string_buffer(32)            
            size = _ssl.BN_bn2bin(bn, ctypes.byref(buf))
            n = uint256_from_str(buf[:size][::-1]+(32-size)*'\x00')
            return n
        x = _bn2bin(x)
        y = _bn2bin(y)
        _ssl.BN_CTX_free(ctx)
        return x,y

    def mult(self, x):
        assert type(x) is long
        result = _ssl.EC_POINT_new(group)
        ctx = _ssl.BN_CTX_new()
        x = _ssl.BN_bin2bn(uint256_to_str(x)[::-1], 32, _ssl.BN_new())
        _ssl.EC_POINT_mul(group, result, None, self.point, x, ctx)
        _ssl.BN_CTX_free(ctx)
        return SPoint(_point=result)

    def __destroy__(self):
        _ssl.EC_POINT_free(self.point)

    def __repr__(self):
        return 'SPoint()'
