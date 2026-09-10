// CPython boundary for the optional native BFV RNS/NTT kernels.
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "rns_ntt.h"
#include <string>

using namespace xtrace_bfv;
namespace {
using RingPtr = std::shared_ptr<const Ring>;
using KeyPtr = std::shared_ptr<const SwitchKey>;
constexpr const char* ring_name = "xtrace.bfv.rns.ring.v1";
constexpr const char* key_name = "xtrace.bfv.rns.key.v1";

struct PythonError {};
struct WithoutGIL {
    PyThreadState* state = PyEval_SaveThread();
    ~WithoutGIL() { PyEval_RestoreThread(state); }
};

template <class T> T get_capsule(PyObject* object, const char* name) {
    auto pointer = static_cast<T*>(PyCapsule_GetPointer(object, name));
    if (!pointer) throw PythonError{};
    return *pointer;
}
template <class T> void delete_capsule(PyObject* capsule) {
    delete static_cast<T*>(PyCapsule_GetPointer(capsule, PyCapsule_GetName(capsule)));
}
template <class T> PyObject* capsule(T value, const char* name) {
    auto owner = std::make_unique<T>(std::move(value));
    PyObject* result = PyCapsule_New(owner.get(), name, delete_capsule<T>);
    if (result) owner.release();
    return result;
}

// Only fixed-width little-endian bytes cross this private kernel boundary.
// Validate lengths and coefficient bounds before any native transform accesses
// memory or relies on its CRT reconstruction bound.
Polynomial read_poly(PyObject* object, const Ring& ring) {
    if (!PyBytes_Check(object)) {
        PyErr_SetString(PyExc_TypeError, "Polynomial must be fixed-width bytes");
        throw PythonError{};
    }
    if (PyBytes_GET_SIZE(object) != static_cast<Py_ssize_t>(ring.n * ring.coefficient_bytes))
        throw std::invalid_argument("Incorrect polynomial byte length");
    const auto* data = PyBytes_AS_STRING(object);
    Polynomial result(ring.n);
    for (std::size_t i = 0; i < ring.n; ++i) {
        mpz_import(result[i].get_mpz_t(), ring.coefficient_bytes, -1, 1, 0, 0,
                   data + i * ring.coefficient_bytes);
        if (result[i] >= ring.q) throw std::invalid_argument("Noncanonical polynomial coefficient");
    }
    return result;
}

std::array<Polynomial, 2> read_pair(PyObject* object, const Ring& ring) {
    if (!PyTuple_Check(object) || PyTuple_GET_SIZE(object) != 2)
        throw std::invalid_argument("Expected two ciphertext components");
    return {read_poly(PyTuple_GET_ITEM(object, 0), ring), read_poly(PyTuple_GET_ITEM(object, 1), ring)};
}

PyObject* write_poly(const Polynomial& poly, const Ring& ring) {
    if (poly.size() != ring.n) throw std::logic_error("Native kernel returned an incorrect polynomial length");
    PyObject* result = PyBytes_FromStringAndSize(nullptr, ring.n * ring.coefficient_bytes);
    if (!result) return nullptr;
    auto* output = PyBytes_AS_STRING(result);
    std::fill(output, output + ring.n * ring.coefficient_bytes, 0);
    for (std::size_t i = 0; i < ring.n; ++i) {
        // All public return paths first reduce into [0,q); keep the guard here
        // so a future kernel mistake cannot overrun a fixed-width buffer.
        if (poly[i] < 0 || poly[i] >= ring.q) {
            Py_DECREF(result);
            throw std::logic_error("Native kernel returned a noncanonical coefficient");
        }
        mpz_export(output + i * ring.coefficient_bytes, nullptr, -1, 1, 0, 0, poly[i].get_mpz_t());
    }
    return result;
}

template <std::size_t Count>
PyObject* write_components(const std::array<Polynomial, Count>& components, const Ring& ring) {
    PyObject* result = PyTuple_New(Count);
    if (!result) return nullptr;
    try {
        for (std::size_t i = 0; i < Count; ++i) {
            PyObject* poly = write_poly(components[i], ring);
            if (!poly) { Py_DECREF(result); return nullptr; }
            PyTuple_SET_ITEM(result, i, poly);
        }
    } catch (...) { Py_DECREF(result); throw; }
    return result;
}

template <class Function> PyObject* checked(Function&& function) {
    try { return function(); }
    catch (const PythonError&) { return nullptr; }
    catch (const std::bad_alloc&) { return PyErr_NoMemory(); }
    catch (const std::invalid_argument& error) { PyErr_SetString(PyExc_ValueError, error.what()); }
    catch (const std::exception& error) { PyErr_SetString(PyExc_RuntimeError, error.what()); }
    return nullptr;
}

PyObject* create_ring(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *n_object, *bits_object;
        const char* q_hex;
        if (!PyArg_ParseTuple(args, "OsO", &n_object, &q_hex, &bits_object)) return nullptr;
        auto n = PyLong_AsUnsignedLongLong(n_object), bits = PyLong_AsUnsignedLongLong(bits_object);
        if (PyErr_Occurred()) return nullptr;
        if (n > 32768 || bits > 512) throw std::invalid_argument("Invalid native BFV ring parameters");
        mpz_class q;
        if (q.set_str(q_hex, 16) != 0) throw std::invalid_argument("Invalid ciphertext modulus");
        RingPtr ring;
        { WithoutGIL release; ring = std::make_shared<Ring>(n, q, bits); }
        return capsule(std::move(ring), ring_name);
    });
}

Word read_t(PyObject* value, const Ring& ring) {
    Word t = PyLong_AsUnsignedLongLong(value);
    if (PyErr_Occurred()) throw PythonError{};
    if (t < 2 || t >= (Word(1) << 60) || mpz_cmp_ui(ring.q.get_mpz_t(), t) <= 0)
        throw std::invalid_argument("Invalid plaintext modulus");
    return t;
}

Word read_exponent(PyObject* value, const Ring& ring) {
    Word exponent = PyLong_AsUnsignedLongLong(value);
    if (PyErr_Occurred()) throw PythonError{};
    if (!(exponent & 1) || exponent >= 2 * ring.n)
        throw std::invalid_argument("Invalid Galois exponent");
    return exponent;
}

PyObject* rotate_rows(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *key_object, *ciphertext_object, *exponent_object;
        if (!PyArg_ParseTuple(args, "OOO", &key_object, &ciphertext_object, &exponent_object)) return nullptr;
        auto key = get_capsule<KeyPtr>(key_object, key_name);
        auto ciphertext = read_pair(ciphertext_object, *key->ring);
        auto exponent = read_exponent(exponent_object, *key->ring);
        Ciphertext result;
        { WithoutGIL release; result = exponent == 1 ? ciphertext : rotate(ciphertext, exponent, *key); }
        return write_components(result, *key->ring);
    });
}

PyObject* hamming_tile(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *key_object, *query_object, *tile_object, *rotations_object, *mask_object, *t_object;
        if (!PyArg_ParseTuple(args, "OOOOOO", &key_object, &query_object, &tile_object,
                             &rotations_object, &mask_object, &t_object)) return nullptr;
        auto relin = get_capsule<KeyPtr>(key_object, key_name);
        const auto& ring = *relin->ring;
        Word t = read_t(t_object, ring);
        auto query = read_pair(query_object, ring), tile = read_pair(tile_object, ring);
        auto mask = read_poly(mask_object, ring);
        if (!PyTuple_Check(rotations_object)) throw std::invalid_argument("Rotations must be a tuple");
        std::vector<std::pair<Word, KeyPtr>> rotations;
        for (Py_ssize_t i = 0; i < PyTuple_GET_SIZE(rotations_object); ++i) {
            auto pair = PyTuple_GET_ITEM(rotations_object, i);
            if (!PyTuple_Check(pair) || PyTuple_GET_SIZE(pair) != 2)
                throw std::invalid_argument("Invalid rotation key entry");
            Word exponent = read_exponent(PyTuple_GET_ITEM(pair, 0), ring);
            auto key = get_capsule<KeyPtr>(PyTuple_GET_ITEM(pair, 1), key_name);
            if (key->ring != relin->ring) throw std::invalid_argument("Rotation key belongs to another native ring");
            rotations.emplace_back(exponent, std::move(key));
        }
        Ciphertext result;
        { WithoutGIL release; result = distance_tile(std::move(query), tile, *relin, rotations, mask, t); }
        return write_components(result, ring);
    });
}

PyObject* compile_key(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *ring_object, *key_object;
        if (!PyArg_ParseTuple(args, "OO", &ring_object, &key_object)) return nullptr;
        auto ring = get_capsule<RingPtr>(ring_object, ring_name);
        if (!PyTuple_Check(key_object) || PyTuple_GET_SIZE(key_object) != static_cast<Py_ssize_t>(ring->digits))
            throw std::invalid_argument("Incorrect gadget digit count");
        std::vector<std::array<Polynomial, 2>> key;
        for (std::size_t i = 0; i < ring->digits; ++i)
            key.push_back(read_pair(PyTuple_GET_ITEM(key_object, i), *ring));
        KeyPtr prepared;
        { WithoutGIL release; prepared = std::make_shared<SwitchKey>(ring, key); }
        return capsule(std::move(prepared), key_name);
    });
}

PyObject* apply_key(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *key_object, *poly_object;
        if (!PyArg_ParseTuple(args, "OO", &key_object, &poly_object)) return nullptr;
        auto key = get_capsule<KeyPtr>(key_object, key_name);
        auto poly = read_poly(poly_object, *key->ring);
        std::array<Polynomial, 2> result;
        { WithoutGIL release; result = key->apply(poly); }
        return write_components(result, *key->ring);
    });
}

PyObject* ring_product(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *ring_object, *lhs_object, *rhs_object;
        if (!PyArg_ParseTuple(args, "OOO", &ring_object, &lhs_object, &rhs_object)) return nullptr;
        auto ring = get_capsule<RingPtr>(ring_object, ring_name);
        auto lhs = read_poly(lhs_object, *ring), rhs = read_poly(rhs_object, *ring);
        Polynomial result;
        {
            WithoutGIL release;
            result = ring->product(lhs, rhs);
            for (auto& value : result) mpz_mod(value.get_mpz_t(), value.get_mpz_t(), ring->q.get_mpz_t());
        }
        return write_poly(result, *ring);
    });
}

PyObject* multiply(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *ring_object, *lhs_object, *rhs_object, *t_object;
        if (!PyArg_ParseTuple(args, "OOOO", &ring_object, &lhs_object, &rhs_object, &t_object)) return nullptr;
        auto ring = get_capsule<RingPtr>(ring_object, ring_name);
        Word t = read_t(t_object, *ring);
        auto lhs = read_pair(lhs_object, *ring);
        bool square = rhs_object == Py_None;
        std::array<Polynomial, 2> rhs;
        if (!square) rhs = read_pair(rhs_object, *ring);
        std::array<Polynomial, 3> result;
        { WithoutGIL release; result = ring->multiply(lhs, rhs, t, square); }
        return write_components(result, *ring);
    });
}

PyObject* ring_info(PyObject*, PyObject* argument) {
    return checked([&]() -> PyObject* {
        auto ring = get_capsule<RingPtr>(argument, ring_name);
        PyObject* primes = PyTuple_New(ring->transforms.size());
        if (!primes) return nullptr;
        for (std::size_t i = 0; i < ring->transforms.size(); ++i) {
            PyObject* value = PyLong_FromUnsignedLongLong(ring->transforms[i].modulus);
            if (!value) { Py_DECREF(primes); return nullptr; }
            PyTuple_SET_ITEM(primes, i, value);
        }
        return Py_BuildValue("{s:N,s:n,s:n,s:s,s:s}", "primes", primes,
                             "switch_prime_count", ring->switch_prime_count,
                             "transform_table_bytes", ring->bytes(), "gmp", gmp_version,
                             "compiler", __VERSION__);
    });
}

PyObject* key_bytes(PyObject*, PyObject* argument) {
    return checked([&]() -> PyObject* {
        return PyLong_FromSize_t(get_capsule<KeyPtr>(argument, key_name)->bytes());
    });
}

PyMethodDef methods[] = {
    {"create_ring", create_ring, METH_VARARGS, "Prepare exact CRT bases and negacyclic NTT tables."},
    {"compile_key", compile_key, METH_VARARGS, "Cache a gadget key in RNS/NTT form."},
    {"apply_key", apply_key, METH_VARARGS, "Evaluate an exact gadget dot product, reduced mod q."},
    {"ring_product", ring_product, METH_VARARGS, "Multiply two canonical polynomials mod q."},
    {"multiply", multiply, METH_VARARGS, "BFV tensor product and exact signed scale-and-round."},
    {"rotate_rows", rotate_rows, METH_VARARGS, "Galois automorphism and public-key switching."},
    {"hamming_tile", hamming_tile, METH_VARARGS, "Evaluate the native Hamming tile circuit."},
    {"ring_info", ring_info, METH_O, "Report public auxiliary-prime and table information."},
    {"key_bytes", key_bytes, METH_O, "Size of cached NTT coefficient arrays."},
    {nullptr, nullptr, 0, nullptr}
};
PyModuleDef module = {PyModuleDef_HEAD_INIT, "_bfv_rns", "Native BFV RNS/NTT CPU kernels.", -1,
                      methods, nullptr, nullptr, nullptr, nullptr};
} // namespace

PyMODINIT_FUNC PyInit__bfv_rns() {
    PyObject* result = PyModule_Create(&module);
    if (result && PyModule_AddIntConstant(result, "ABI_VERSION", 1) < 0) {
        Py_DECREF(result); return nullptr;
    }
    return result;
}
