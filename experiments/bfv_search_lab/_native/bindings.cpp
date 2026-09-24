// Bounded CPython boundary for the isolated BGV research backend.
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "trace_server.h"
#include <string>

namespace {
using namespace cuhepy_bgv_lab;
using ServerPtr = std::shared_ptr<const Server>;
struct Index {
    ServerPtr server;
    std::vector<PreparedCiphertext> tiles;
};
using IndexPtr = std::shared_ptr<const Index>;
constexpr const char* server_name = "cuhepy.lab.bgv.server.v1";
constexpr const char* index_name = "cuhepy.lab.bgv.index.v1";
struct PythonError {};
struct WithoutGIL {
    PyThreadState* state = PyEval_SaveThread();
    ~WithoutGIL() { PyEval_RestoreThread(state); }
};
template<class Function> PyObject* checked(Function&& f) {
    try { return f(); }
    catch (const PythonError&) { return nullptr; }
    catch (const std::bad_alloc&) { return PyErr_NoMemory(); }
    catch (const std::invalid_argument& e) { PyErr_SetString(PyExc_ValueError, e.what()); }
    catch (const std::exception& e) { PyErr_SetString(PyExc_RuntimeError, e.what()); }
    return nullptr;
}
template<class T> T get(PyObject* object, const char* name) {
    auto p = static_cast<T*>(PyCapsule_GetPointer(object, name));
    if (!p) throw PythonError{};
    return *p;
}
template<class T> void destroy(PyObject* object) {
    delete static_cast<T*>(PyCapsule_GetPointer(object, PyCapsule_GetName(object)));
}
template<class T> PyObject* capsule(T value, const char* name) {
    auto p = std::make_unique<T>(std::move(value));
    auto result = PyCapsule_New(p.get(), name, destroy<T>);
    if (result) p.release();
    return result;
}
std::size_t integer(PyObject* object, std::size_t maximum) {
    if (!PyLong_CheckExact(object)) throw std::invalid_argument("Expected integer native parameter");
    auto value = PyLong_AsSize_t(object);
    if (PyErr_Occurred()) throw PythonError{};
    if (value > maximum) throw std::invalid_argument("Oversized native parameter");
    return value;
}
Polynomial read_poly(PyObject* object, const Ring& r) {
    if (!PyBytes_Check(object) || PyBytes_GET_SIZE(object) != static_cast<Py_ssize_t>(r.n * r.coefficient_bytes))
        throw std::invalid_argument("Incorrect fixed-width polynomial bytes");
    Polynomial result(r.n);
    for (std::size_t i = 0; i < r.n; ++i) {
        mpz_import(result[i].get_mpz_t(), r.coefficient_bytes, -1, 1, 0, 0,
                   PyBytes_AS_STRING(object) + i * r.coefficient_bytes);
        if (result[i] >= r.q) throw std::invalid_argument("Noncanonical polynomial coefficient");
    }
    return result;
}
Ciphertext read_pair(PyObject* object, const Ring& r) {
    if (!PyTuple_Check(object) || PyTuple_GET_SIZE(object) != 2)
        throw std::invalid_argument("Expected two ciphertext components");
    return {read_poly(PyTuple_GET_ITEM(object, 0), r), read_poly(PyTuple_GET_ITEM(object, 1), r)};
}
PyObject* write_pair(const Ciphertext& ct, const Ring& r) {
    auto result = PyTuple_New(2);
    if (!result) return nullptr;
    for (std::size_t k = 0; k < 2; ++k) {
        auto bytes = PyBytes_FromStringAndSize(nullptr, r.n * r.coefficient_bytes);
        if (!bytes) { Py_DECREF(result); return nullptr; }
        PyTuple_SET_ITEM(result, k, bytes);
        auto data = PyBytes_AS_STRING(bytes);
        std::fill(data, data + r.n * r.coefficient_bytes, 0);
        if (ct[k].size() != r.n) {
            Py_DECREF(result); throw std::logic_error("Incorrect output polynomial length");
        }
        for (std::size_t i = 0; i < r.n; ++i) {
            if (ct[k][i] < 0 || ct[k][i] >= r.q) {
                Py_DECREF(result); throw std::logic_error("Noncanonical native output");
            }
            mpz_export(data + i * r.coefficient_bytes, nullptr, -1, 1, 0, 0, ct[k][i].get_mpz_t());
        }
    }
    return result;
}
PyObject* create_server(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *n_obj, *bits_obj, *d_obj, *keys_obj;
        const char* text;
        Py_ssize_t length;
        if (!PyArg_ParseTuple(args, "Os#OOO", &n_obj, &text, &length, &bits_obj, &d_obj, &keys_obj)) return nullptr;
        auto n = integer(n_obj, 32768), bits = integer(bits_obj, 60), d = integer(d_obj, n / 2);
        if (n < 8 || (n & (n - 1)) || bits < 4 || !d || (d & (d - 1)) ||
            length < 8 || length > 60 || text[0] == '0' || !std::all_of(text, text + length, [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            })) throw std::invalid_argument("Invalid native BGV parameters");
        mpz_class q;
        q.set_str(text, 16);
        auto q_bits = mpz_sizeinbase(q.get_mpz_t(), 2);
        if (q_bits < 32 || q_bits > 240 || bits > q_bits || mpz_even_p(q.get_mpz_t()))
            throw std::invalid_argument("Invalid native BGV modulus");
        std::size_t count = 1;
        for (auto shift = d / 2; shift; shift /= 2) ++count;
        if (!PyTuple_Check(keys_obj) || PyTuple_GET_SIZE(keys_obj) != static_cast<Py_ssize_t>(count))
            throw std::invalid_argument("Incorrect native key count");
        std::shared_ptr<const Ring> ring;
        { WithoutGIL release; ring = std::make_shared<Ring>(n, q, bits, true); }
        std::vector<std::shared_ptr<const SwitchKey>> keys;
        for (std::size_t i = 0; i < count; ++i) {
            auto key = PyTuple_GET_ITEM(keys_obj, i);
            if (!PyTuple_Check(key) || PyTuple_GET_SIZE(key) != static_cast<Py_ssize_t>(ring->digits))
                throw std::invalid_argument("Incorrect native gadget digit count");
            std::vector<Ciphertext> columns;
            for (std::size_t j = 0; j < ring->digits; ++j)
                columns.push_back(read_pair(PyTuple_GET_ITEM(key, j), *ring));
            { WithoutGIL release; keys.push_back(std::make_shared<SwitchKey>(ring, columns)); }
        }
        return capsule(ServerPtr(std::make_shared<Server>(ring, d, std::move(keys))), server_name);
    });
}
PyObject* prepare_index(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *server_obj, *tiles;
        if (!PyArg_ParseTuple(args, "OO", &server_obj, &tiles)) return nullptr;
        auto server = get<ServerPtr>(server_obj, server_name);
        if (!PyTuple_Check(tiles)) throw std::invalid_argument("Expected index tuple");
        auto count = static_cast<std::size_t>(PyTuple_GET_SIZE(tiles));
        auto per_tile = 2 * server->primes * server->ring->n * sizeof(Word);
        if (count > 4096 || count > (std::size_t(1) << 31) / per_tile)
            throw std::invalid_argument("Research index exceeds native allocation limit");
        auto index = std::make_shared<Index>();
        index->server = server;
        for (std::size_t i = 0; i < count; ++i) {
            auto tile = read_pair(PyTuple_GET_ITEM(tiles, i), *server->ring);
            { WithoutGIL release; index->tiles.push_back(server->prepare(tile)); }
        }
        return capsule(IndexPtr(index), index_name);
    });
}
PyObject* search(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *server_obj, *query_obj, *index_obj, *mode;
        if (!PyArg_ParseTuple(args, "OOOO", &server_obj, &query_obj, &index_obj, &mode)) return nullptr;
        auto server = get<ServerPtr>(server_obj, server_name);
        auto index = get<IndexPtr>(index_obj, index_name);
        if (index->server != server) throw std::invalid_argument("Index belongs to another native server");
        if (!PyBool_Check(mode)) throw std::invalid_argument("Butterfly mode must be bool");
        auto query = read_pair(query_obj, *server->ring);
        std::vector<Ciphertext> output;
        { WithoutGIL release; output = server->search(query, index->tiles, mode == Py_True); }
        auto result = PyTuple_New(output.size());
        if (!result) return nullptr;
        try {
            for (std::size_t i = 0; i < output.size(); ++i) {
                auto pair = write_pair(output[i], *server->ring);
                if (!pair) { Py_DECREF(result); return nullptr; }
                PyTuple_SET_ITEM(result, i, pair);
            }
        } catch (...) { Py_DECREF(result); throw; }
        return result;
    });
}
PyMethodDef methods[] = {
    {"create_server", create_server, METH_VARARGS, "Compile public trace evaluation keys."},
    {"prepare_index", prepare_index, METH_VARARGS, "Cache public encrypted index transforms."},
    {"search", search, METH_VARARGS, "Evaluate the per-tile or joint trace circuit."},
    {nullptr, nullptr, 0, nullptr}
};
PyModuleDef module = {PyModuleDef_HEAD_INIT, "_bgv_trace", "Experimental public BGV arithmetic.", -1,
                     methods, nullptr, nullptr, nullptr, nullptr};
}
PyMODINIT_FUNC PyInit__bgv_trace() { return PyModule_Create(&module); }
