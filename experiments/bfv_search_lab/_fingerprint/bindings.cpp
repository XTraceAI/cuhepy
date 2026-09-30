// E37 research word arithmetic for hidden integrity challenges.
// No HE secret is accepted. This is not a constant-time integrity-key audit.
// Independent GMP oracles remain authoritative. All buffers are little-endian.
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <array>
#include <cstdint>
#include <stdexcept>

using u64 = std::uint64_t;
using u128 = unsigned __int128;

struct Bytes {
    const unsigned char *data;
    Py_ssize_t size;
    explicit Bytes(PyObject *object) {
        if (!PyBytes_Check(object)) throw std::invalid_argument("Expected immutable bytes");
        data = reinterpret_cast<const unsigned char *>(PyBytes_AS_STRING(object));
        size = PyBytes_GET_SIZE(object);
    }
};

static u64 load(const unsigned char *p, int width = 8) {
    u64 value = 0;
    for (int j = 0; j < width; ++j) value |= static_cast<u64>(p[j]) << (8 * j);
    return value;
}

static void save(unsigned char *p, u64 value) {
    for (int j = 0; j < 8; ++j) p[j] = static_cast<unsigned char>(value >> (8 * j));
}

static void modulus(u64 q) {
    if (q < 3 || q >= (u64(1) << 56)) throw std::invalid_argument("Expected a bounded word modulus");
    // Primality/irreducibility are checked by the Python constructors.
}

static void words(const Bytes &body, u64 q) {
    if (body.size % 8 || body.size < 8 || body.size / 8 > (1 << 20))
        throw std::invalid_argument("Invalid bounded coefficient body");
    for (Py_ssize_t i = 0; i < body.size; i += 8)
        if (load(body.data + i) >= q) throw std::invalid_argument("Noncanonical coefficient");
}

static int key(const Bytes &body, u64 q, std::array<u64, 8> &coefficients) {
    if (body.size % 8 || body.size < 8 || body.size > 64)
        throw std::invalid_argument("Invalid bounded monic-key lower coefficients");
    const int degree = static_cast<int>(body.size / 8);
    for (int j = 0; j < degree; ++j) {
        coefficients[j] = load(body.data + 8 * j);
        if (coefficients[j] >= q) throw std::invalid_argument("Noncanonical key coefficient");
    }
    return degree;
}

static void step(std::array<u64, 8> &state, const std::array<u64, 8> &f, int degree, u64 q, u64 value) {
    const u64 high = state[degree - 1];
    for (int j = degree - 1; j >= 1; --j) {
        const u64 product = static_cast<u64>(u128(high) * f[j] % q);
        state[j] = state[j - 1] >= product ? state[j - 1] - product : q - (product - state[j - 1]);
    }
    const u64 product = static_cast<u64>(u128(high) * f[0] % q);
    state[0] = value >= product ? value - product : q - (product - value);
}

static PyObject *remainder(PyObject *, PyObject *args) {
    PyObject *values, *polynomial;
    unsigned long long q_raw;
    if (!PyArg_ParseTuple(args, "OOK", &values, &polynomial, &q_raw)) return nullptr;
    try {
        const u64 q = q_raw;
        modulus(q);
        Bytes body(values), fbody(polynomial);
        words(body, q);
        std::array<u64, 8> f{}, state{};
        const int degree = key(fbody, q, f);
        Py_BEGIN_ALLOW_THREADS
        for (Py_ssize_t i = body.size - 8; i >= 0; i -= 8) step(state, f, degree, q, load(body.data + i));
        Py_END_ALLOW_THREADS
        PyObject *result = PyBytes_FromStringAndSize(nullptr, degree * 8);
        if (!result) return nullptr;
        auto *out = reinterpret_cast<unsigned char *>(PyBytes_AS_STRING(result));
        for (int j = 0; j < degree; ++j) save(out + 8 * j, state[j]);
        return result;
    } catch (const std::exception &error) {
        PyErr_SetString(PyExc_ValueError, error.what());
        return nullptr;
    }
}

static PyObject *powers(PyObject *, PyObject *args) {
    PyObject *polynomial;
    Py_ssize_t length;
    unsigned long long q_raw;
    if (!PyArg_ParseTuple(args, "nOK", &length, &polynomial, &q_raw)) return nullptr;
    try {
        const u64 q = q_raw;
        modulus(q);
        if (length < 1 || length > (1 << 20)) throw std::invalid_argument("Invalid bounded challenge length");
        Bytes fbody(polynomial);
        std::array<u64, 8> f{}, state{};
        const int degree = key(fbody, q, f);
        state[0] = 1;
        PyObject *result = PyBytes_FromStringAndSize(nullptr, length * degree * 8);
        if (!result) return nullptr;
        auto *out = reinterpret_cast<unsigned char *>(PyBytes_AS_STRING(result));
        Py_BEGIN_ALLOW_THREADS
        for (Py_ssize_t i = 0; i < length; ++i) {
            for (int j = 0; j < degree; ++j) save(out + (j * length + i) * 8, state[j]);
            step(state, f, degree, q, 0);
        }
        Py_END_ALLOW_THREADS
        return result;
    } catch (const std::exception &error) {
        PyErr_SetString(PyExc_ValueError, error.what());
        return nullptr;
    }
}

static PyObject *uniform_dot(PyObject *, PyObject *args) {
    PyObject *values, *randomness;
    Py_ssize_t width, bits, offset;
    unsigned long long q_raw;
    if (!PyArg_ParseTuple(args, "OOnnKn", &values, &randomness, &width, &bits, &q_raw, &offset)) return nullptr;
    try {
        const u64 q = q_raw;
        modulus(q);
        Bytes body(values), raw(randomness);
        words(body, q);
        const Py_ssize_t length = body.size / 8;
        if (bits < 2 || bits > 56 || width != (bits + 7) / 8 || q >= (u64(1) << bits)
                || q < (u64(1) << (bits - 1)) || raw.size % width || raw.size / width > (1 << 20)
                || offset < 0 || offset > length)
            throw std::invalid_argument("Invalid uniform sampling body/offset");
        const u64 mask = (u64(1) << bits) - 1;
        Py_ssize_t i = offset;
        u128 total = 0;
        Py_BEGIN_ALLOW_THREADS
        for (Py_ssize_t j = 0; j < raw.size && i < length; j += width) {
            const u64 candidate = load(raw.data + j, static_cast<int>(width)) & mask;
            if (candidate < q) {
                total += u128(load(body.data + 8 * i)) * candidate;
                ++i;
                // At most 64 products of <2^56 words before reduction:
                // <2^118, safely inside u128 even on the largest input.
                if ((i - offset) % 64 == 0) total %= q;
            }
        }
        Py_END_ALLOW_THREADS
        return Py_BuildValue("nK", i - offset, static_cast<unsigned long long>(total % q));
    } catch (const std::exception &error) {
        PyErr_SetString(PyExc_ValueError, error.what());
        return nullptr;
    }
}

static PyObject *pack_bits(PyObject *, PyObject *args) {
    PyObject *values;
    Py_ssize_t bits;
    unsigned long long q_raw;
    if (!PyArg_ParseTuple(args, "OnK", &values, &bits, &q_raw)) return nullptr;
    try {
        const u64 q = q_raw;
        modulus(q);
        Bytes body(values);
        words(body, q);
        if (bits < 2 || bits > 56 || q >= (u64(1) << bits) || q < (u64(1) << (bits - 1)))
            throw std::invalid_argument("Incorrect pinned coefficient bit width");
        const Py_ssize_t length = body.size / 8;
        PyObject *result = PyBytes_FromStringAndSize(nullptr, (length * bits + 7) / 8);
        if (!result) return nullptr;
        auto *out = reinterpret_cast<unsigned char *>(PyBytes_AS_STRING(result));
        u64 pending = 0;
        int available = 0;
        Py_ssize_t offset = 0;
        Py_BEGIN_ALLOW_THREADS
        for (Py_ssize_t i = 0; i < length; ++i) {
            pending |= load(body.data + 8 * i) << available;
            available += static_cast<int>(bits);
            while (available >= 8) {
                out[offset++] = static_cast<unsigned char>(pending);
                pending >>= 8;
                available -= 8;
            }
        }
        if (available) out[offset] = static_cast<unsigned char>(pending);
        Py_END_ALLOW_THREADS
        return result;
    } catch (const std::exception &error) {
        PyErr_SetString(PyExc_ValueError, error.what());
        return nullptr;
    }
}

static PyObject *unpack_bits(PyObject *, PyObject *args) {
    PyObject *values;
    Py_ssize_t bits, length;
    unsigned long long q_raw;
    if (!PyArg_ParseTuple(args, "OnnK", &values, &bits, &length, &q_raw)) return nullptr;
    try {
        const u64 q = q_raw;
        modulus(q);
        Bytes body(values);
        if (bits < 2 || bits > 56 || q >= (u64(1) << bits) || q < (u64(1) << (bits - 1))
                || length < 1 || length > (1 << 20) || body.size != (length * bits + 7) / 8)
            throw std::invalid_argument("Incorrect pinned coefficient count/width/body");
        const int tail = static_cast<int>((length * bits) % 8);
        if (tail && (body.data[body.size - 1] >> tail))
            throw std::invalid_argument("Nonzero coefficient-body padding");
        PyObject *result = PyBytes_FromStringAndSize(nullptr, length * 8);
        if (!result) return nullptr;
        auto *out = reinterpret_cast<unsigned char *>(PyBytes_AS_STRING(result));
        const u64 mask = (u64(1) << bits) - 1;
        u64 pending = 0;
        int available = 0;
        Py_ssize_t offset = 0;
        bool invalid = false;
        Py_BEGIN_ALLOW_THREADS
        for (Py_ssize_t i = 0; i < length; ++i) {
            while (available < bits) {
                pending |= static_cast<u64>(body.data[offset++]) << available;
                available += 8;
            }
            const u64 value = pending & mask;
            if (value >= q) { invalid = true; break; }
            save(out + 8 * i, value);
            pending >>= bits;
            available -= static_cast<int>(bits);
        }
        Py_END_ALLOW_THREADS
        if (invalid) {
            Py_DECREF(result);
            throw std::invalid_argument("Noncanonical coefficient residue");
        }
        return result;
    } catch (const std::exception &error) {
        PyErr_SetString(PyExc_ValueError, error.what());
        return nullptr;
    }
}

static PyMethodDef methods[] = {
    {"remainder", remainder, METH_VARARGS, nullptr},
    {"powers", powers, METH_VARARGS, nullptr},
    {"uniform_dot", uniform_dot, METH_VARARGS, nullptr},
    {"pack_bits", pack_bits, METH_VARARGS, nullptr},
    {"unpack_bits", unpack_bits, METH_VARARGS, nullptr},
    {nullptr, nullptr, 0, nullptr}
};
static PyModuleDef module = {PyModuleDef_HEAD_INIT, "_fingerprint", nullptr, -1, methods, nullptr, nullptr, nullptr, nullptr};
PyMODINIT_FUNC PyInit__fingerprint() {
    PyObject *result = PyModule_Create(&module);
    if (result && PyModule_AddIntConstant(result, "ABI_VERSION", 1) < 0) {
        Py_DECREF(result);
        return nullptr;
    }
    return result;
}
