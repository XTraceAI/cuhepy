// E29: public linear correction in Y=X^(N/S), retaining full degree-N RLWE.
// Independent small negacyclic NTTs on each coefficient fiber. No HE secrets,
// external HE library, key switches, ciphertext products or modulus rounding.
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {
using Word = std::uint64_t;
using Wide = __uint128_t;
constexpr const char* NAME = "cuhepy.research.crt_subring.v1";

Word product(Word a, Word b, Word q) { return static_cast<Word>(Wide(a) * b % q); }
Word power(Word a, Word k, Word q) {
    Word r = 1;
    while (k) {
        if (k & 1) r = product(r, a, q);
        a = product(a, a, q);
        k >>= 1;
    }
    return r;
}

Word read_word(const char* p) {
    Word x = 0;
    for (unsigned i = 0; i < 8; ++i) x |= Word(static_cast<unsigned char>(p[i])) << (8 * i);
    return x;
}
void write_word(char* p, Word x) {
    for (unsigned i = 0; i < 8; ++i) p[i] = static_cast<char>(x >> (8 * i));
}
const char* bytes(PyObject* value, std::size_t size) {
    if (!PyBytes_Check(value) || PyBytes_GET_SIZE(value) != static_cast<Py_ssize_t>(size))
        throw std::invalid_argument("Incorrect subring word buffer");
    return PyBytes_AS_STRING(value);
}

struct Index {
    std::size_t n, slots, columns, replies, stride;
    Word q, psi, omega, inverse_omega, inverse_slots;
    std::vector<Word> twists, inverse_twists, transformed;

    Index(std::size_t n_, std::size_t s, std::size_t f, std::size_t r, Word q_, Word psi_)
        : n(n_), slots(s), columns(f), replies(r), stride(n_ / s), q(q_), psi(psi_),
          omega(product(psi_, psi_, q_)), inverse_omega(power(omega, q_ - 2, q_)),
          inverse_slots(power(s, q_ - 2, q_)), twists(s), inverse_twists(s),
          transformed(f * r * 2 * n_) {
        twists[0] = inverse_twists[0] = 1;
        Word inverse = power(psi, q - 2, q);
        for (std::size_t k = 1; k < slots; ++k) {
            twists[k] = product(twists[k - 1], psi, q);
            inverse_twists[k] = product(inverse_twists[k - 1], inverse, q);
        }
    }

    void ntt(std::vector<Word>& a, bool inverse) const {
        for (std::size_t i = 1, j = 0; i < slots; ++i) {
            std::size_t bit = slots >> 1;
            for (; j & bit; bit >>= 1) j ^= bit;
            j ^= bit;
            if (i < j) std::swap(a[i], a[j]);
        }
        for (std::size_t length = 2; length <= slots; length <<= 1) {
            Word step = power(inverse ? inverse_omega : omega, slots / length, q);
            for (std::size_t start = 0; start < slots; start += length) {
                Word twiddle = 1;
                for (std::size_t j = 0; j < length / 2; ++j) {
                    Word u = a[start + j], v = product(a[start + j + length / 2], twiddle, q);
                    a[start + j] = (u + v >= q) ? u + v - q : u + v;
                    a[start + j + length / 2] = (u >= v) ? u - v : u + q - v;
                    twiddle = product(twiddle, step, q);
                }
            }
        }
        if (inverse) for (Word& x : a) x = product(x, inverse_slots, q);
    }

    void prepare(const char* data) {
        std::vector<Word> a(slots);
        for (std::size_t p = 0; p < columns * replies * 2; ++p) {
            for (std::size_t r = 0; r < stride; ++r) {
                for (std::size_t k = 0; k < slots; ++k) {
                    Word x = read_word(data + 8 * (p * n + k * stride + r));
                    if (x >= q) throw std::invalid_argument("Noncanonical enrolled coefficient");
                    a[k] = product(x, twists[k], q);
                }
                ntt(a, false);
                for (std::size_t k = 0; k < slots; ++k) transformed[p * n + k * stride + r] = a[k];
            }
        }
    }

    void evaluate(const char* corrections, const char* saved, char* output) const {
        std::vector<Word> weights(columns * slots), a(slots), accumulator(replies * 2 * n, 0);
        for (std::size_t j = 0; j < columns; ++j) {
            for (std::size_t k = 0; k < slots; ++k) {
                Word bits = read_word(corrections + 8 * (j * slots + k));
                std::int64_t signed_value;
                std::memcpy(&signed_value, &bits, sizeof(bits));
                auto residue = signed_value % static_cast<std::int64_t>(q);
                a[k] = product(static_cast<Word>(residue < 0 ? residue + q : residue), twists[k], q);
            }
            ntt(a, false);
            for (std::size_t k = 0; k < slots; ++k) weights[j * slots + k] = a[k];
        }
        for (std::size_t j = 0; j < columns; ++j) {
            for (std::size_t p = 0; p < replies * 2; ++p) {
                for (std::size_t k = 0; k < slots; ++k) {
                    Word w = weights[j * slots + k];
                    for (std::size_t r = 0; r < stride; ++r) {
                        std::size_t at = p * n + k * stride + r;
                        Word value = product(w, transformed[(j * replies * 2 + p) * n + k * stride + r], q);
                        Word sum = accumulator[at] + value;
                        accumulator[at] = sum >= q ? sum - q : sum;
                    }
                }
            }
        }
        for (std::size_t p = 0; p < replies * 2; ++p) {
            for (std::size_t r = 0; r < stride; ++r) {
                for (std::size_t k = 0; k < slots; ++k) a[k] = accumulator[p * n + k * stride + r];
                ntt(a, true);
                for (std::size_t k = 0; k < slots; ++k) {
                    std::size_t at = p * n + k * stride + r;
                    Word offset = read_word(saved + 8 * at);
                    if (offset >= q) throw std::invalid_argument("Noncanonical offline coefficient");
                    Word value = product(a[k], inverse_twists[k], q) + offset;
                    write_word(output + 8 * at, value >= q ? value - q : value);
                }
            }
        }
    }
};

void destroy(PyObject* capsule) { delete static_cast<Index*>(PyCapsule_GetPointer(capsule, NAME)); }
template<class F> PyObject* guarded(F&& f) {
    try { return f(); }
    catch (const std::bad_alloc&) { return PyErr_NoMemory(); }
    catch (const std::invalid_argument& e) { PyErr_SetString(PyExc_ValueError, e.what()); }
    catch (const std::exception& e) { PyErr_SetString(PyExc_RuntimeError, e.what()); }
    return nullptr;
}

PyObject* prepare(PyObject*, PyObject* args) {
    Py_ssize_t n, slots, columns, replies;
    unsigned long long q, psi;
    PyObject* data;
    if (!PyArg_ParseTuple(args, "nnnnKKO", &n, &slots, &columns, &replies, &q, &psi, &data)) return nullptr;
    return guarded([&]() -> PyObject* {
        // Primality is checked by the Python adapter. Root/order/inverses are
        // also checked here; this raw module is not a network-facing parser.
        if (n < 8 || n > 32768 || (n & (n - 1)) || slots < 1 || slots > 64 || (slots & (slots - 1))
            || slots > n || columns < 1 || columns > 512 || replies < 0 || replies > 64
            || q < 3 || q >= (Word(1) << 60) || psi >= q || (q - 1) % (2 * slots)
            || power(psi, slots, q) != q - 1 || product(slots, power(slots, q - 2, q), q) != 1
            || std::size_t(columns) * replies * 2 * n > (std::size_t(1) << 24))
            throw std::invalid_argument("Invalid bounded subring NTT context");
        const char* input = bytes(data, std::size_t(columns) * replies * 2 * n * 8);
        auto index = std::make_unique<Index>(n, slots, columns, replies, q, psi);
        index->prepare(input);
        PyObject* result = PyCapsule_New(index.get(), NAME, destroy);
        if (result) index.release();
        return result;
    });
}

PyObject* evaluate(PyObject*, PyObject* args) {
    PyObject *capsule, *corrections, *saved;
    if (!PyArg_ParseTuple(args, "OOO", &capsule, &corrections, &saved)) return nullptr;
    auto* index = static_cast<Index*>(PyCapsule_GetPointer(capsule, NAME));
    if (!index) return nullptr;
    return guarded([&]() -> PyObject* {
        const char* a = bytes(corrections, index->columns * index->slots * 8);
        std::size_t size = index->replies * 2 * index->n * 8;
        const char* y = bytes(saved, size);
        PyObject* result = PyBytes_FromStringAndSize(nullptr, size);
        if (!result) return nullptr;
        try { index->evaluate(a, y, PyBytes_AS_STRING(result)); }
        catch (...) { Py_DECREF(result); throw; }
        return result;
    });
}

PyMethodDef methods[] = {
    {"prepare", prepare, METH_VARARGS, "Prepare immutable public coefficient fibers."},
    {"evaluate", evaluate, METH_VARARGS, "Evaluate a full unrounded public response."},
    {nullptr, nullptr, 0, nullptr}
};
PyModuleDef module = {PyModuleDef_HEAD_INIT, "_crt_subring", nullptr, -1, methods, nullptr, nullptr, nullptr, nullptr};
}  // namespace
PyMODINIT_FUNC PyInit__crt_subring() {
    PyObject* result = PyModule_Create(&module);
    if (result) PyModule_AddIntConstant(result, "ABI_VERSION", 1);
    return result;
}
