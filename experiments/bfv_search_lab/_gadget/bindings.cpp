// Isolated bounded public research boundary. Reuses the repository's CPython
// capsule/fixed-coefficient conventions; never receives a secret or permission
// to decrypt. Trusted owner phase metadata is checked by the Python caller.
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "propagated_server.h"

namespace {
using namespace cuhepy_bgv_lab;
using Plan = std::shared_ptr<const PropagatedGadgetServer>;
struct Index { Plan plan; std::vector<PreparedCiphertext> tiles; };
using Prepared = std::shared_ptr<const Index>;
constexpr auto plan_name = "cuhepy.lab.bgv.propagated.plan.v1";
constexpr auto index_name = "cuhepy.lab.bgv.propagated.index.v1";
struct PythonError {};
struct WithoutGIL {
    PyThreadState* state = PyEval_SaveThread();
    ~WithoutGIL() { PyEval_RestoreThread(state); }
};
template<class F> PyObject* checked(F&& f) {
    try { return f(); }
    catch (const PythonError&) { return nullptr; }
    catch (const std::bad_alloc&) { return PyErr_NoMemory(); }
    catch (const std::invalid_argument& e) { PyErr_SetString(PyExc_ValueError, e.what()); }
    catch (const std::exception& e) { PyErr_SetString(PyExc_RuntimeError, e.what()); }
    return nullptr;
}
template<class T> T get(PyObject* obj, const char* name) {
    auto p = static_cast<T*>(PyCapsule_GetPointer(obj, name));
    if (!p) throw PythonError{};
    return *p;
}
template<class T> void destroy(PyObject* obj) {
    delete static_cast<T*>(PyCapsule_GetPointer(obj, PyCapsule_GetName(obj)));
}
template<class T> PyObject* capsule(T value, const char* name) {
    auto ptr = std::make_unique<T>(std::move(value));
    auto result = PyCapsule_New(ptr.get(), name, destroy<T>);
    if (result) ptr.release();
    return result;
}
std::size_t integer(PyObject* obj, std::size_t maximum) {
    if (!PyLong_CheckExact(obj)) throw std::invalid_argument("Exact integer required");
    auto value = PyLong_AsSize_t(obj);
    if (PyErr_Occurred()) throw PythonError{};
    if (value > maximum) throw std::invalid_argument("Oversized parameter");
    return value;
}
Polynomial polynomial(PyObject* obj, const Ring& ring) {
    if (!PyBytes_CheckExact(obj) || PyBytes_GET_SIZE(obj) != Py_ssize_t(ring.n * ring.coefficient_bytes))
        throw std::invalid_argument("Incorrect fixed-width polynomial");
    Polynomial out(ring.n);
    for (std::size_t i = 0; i < ring.n; ++i) {
        mpz_import(out[i].get_mpz_t(), ring.coefficient_bytes, -1, 1, 0, 0,
                   PyBytes_AS_STRING(obj) + i * ring.coefficient_bytes);
        if (out[i] >= ring.q) throw std::invalid_argument("Noncanonical coefficient");
    }
    return out;
}
Ciphertext pair(PyObject* obj, const Ring& ring) {
    if (!PyTuple_CheckExact(obj) || PyTuple_GET_SIZE(obj) != 2)
        throw std::invalid_argument("Exact pair required");
    return {polynomial(PyTuple_GET_ITEM(obj, 0), ring), polynomial(PyTuple_GET_ITEM(obj, 1), ring)};
}
PyObject* create(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *n_obj, *d_obj, *keys_obj, *enabled;
        const char* text;
        Py_ssize_t length;
        if (!PyArg_ParseTuple(args, "Os#OOO", &n_obj, &text, &length, &d_obj, &keys_obj, &enabled)) return nullptr;
        auto n = integer(n_obj, 16384), d = integer(d_obj, n / 2);
        if (n < 8 || (n & (n - 1)) || !d || (d & (d - 1)) || !PyBool_Check(enabled)
            || length != 30 || text[0] == '0' || !std::all_of(text, text + length, [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }))
            throw std::invalid_argument("Invalid fixed Q120 prototype context");
        mpz_class q;
        q.set_str(text, 16);
        if (mpz_sizeinbase(q.get_mpz_t(), 2) != 120)
            throw std::invalid_argument("Q120 required");
        std::size_t count = 1;
        for (auto shift = d / 2; shift; shift /= 2) ++count;
        if (!PyTuple_CheckExact(keys_obj) || PyTuple_GET_SIZE(keys_obj) != Py_ssize_t(count))
            throw std::invalid_argument("Incorrect key coverage");
        std::shared_ptr<const Ring> ring;
        { WithoutGIL release; ring = std::make_shared<Ring>(n, q, 30, true, true, 2); }
        std::vector<std::shared_ptr<const SwitchKey>> keys;
        for (std::size_t i = 0; i < count; ++i) {
            auto key = PyTuple_GET_ITEM(keys_obj, i);
            if (!PyTuple_CheckExact(key) || PyTuple_GET_SIZE(key) != 4)
                throw std::invalid_argument("Four common gadget columns required");
            std::vector<Ciphertext> columns;
            for (std::size_t j = 0; j < 4; ++j) columns.push_back(pair(PyTuple_GET_ITEM(key, j), *ring));
            { WithoutGIL release; keys.push_back(std::make_shared<SwitchKey>(ring, columns)); }
        }
        Plan plan;
        { WithoutGIL release; plan = std::make_shared<PropagatedGadgetServer>(ring, d, std::move(keys), enabled == Py_True); }
        return capsule(std::move(plan), plan_name);
    });
}
PyObject* prepare(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *plan_obj, *tiles;
        if (!PyArg_ParseTuple(args, "OO", &plan_obj, &tiles)) return nullptr;
        auto plan = get<Plan>(plan_obj, plan_name);
        if (!PyTuple_CheckExact(tiles)) throw std::invalid_argument("Exact tile tuple required");
        auto count = std::size_t(PyTuple_GET_SIZE(tiles));
        if (!count || count > 4096 || count * 4 * plan->ring->n * sizeof(Word) > (std::size_t(1) << 31))
            throw std::invalid_argument("Index allocation bound exceeded");
        auto index = std::make_shared<Index>();
        index->plan = plan;
        for (std::size_t i = 0; i < count; ++i) {
            auto cipher = pair(PyTuple_GET_ITEM(tiles, i), *plan->ring);
            { WithoutGIL release; index->tiles.push_back(plan->prepare(cipher)); }
        }
        return capsule(Prepared(index), index_name);
    });
}
PyObject* write(const Ciphertext& cipher, const Ring& ring) {
    auto out = PyTuple_New(2);
    if (!out) return nullptr;
    for (std::size_t k = 0; k < 2; ++k) {
        auto data = PyBytes_FromStringAndSize(nullptr, ring.n * ring.coefficient_bytes);
        if (!data) { Py_DECREF(out); return nullptr; }
        PyTuple_SET_ITEM(out, k, data);
        std::fill(PyBytes_AS_STRING(data), PyBytes_AS_STRING(data) + PyBytes_GET_SIZE(data), 0);
        for (std::size_t i = 0; i < ring.n; ++i) {
            if (cipher[k][i] < 0 || cipher[k][i] >= ring.q) {
                Py_DECREF(out); throw std::logic_error("Noncanonical output");
            }
            mpz_export(PyBytes_AS_STRING(data) + i * ring.coefficient_bytes, nullptr, -1, 1, 0, 0, cipher[k][i].get_mpz_t());
        }
    }
    return out;
}
PyObject* search(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *plan_obj, *query_obj, *index_obj;
        if (!PyArg_ParseTuple(args, "OOO", &plan_obj, &query_obj, &index_obj)) return nullptr;
        auto plan = get<Plan>(plan_obj, plan_name);
        auto index = get<Prepared>(index_obj, index_name);
        if (index->plan != plan) throw std::invalid_argument("Mixed index/plan context");
        auto query = pair(query_obj, *plan->ring);
        std::vector<Ciphertext> output;
        { WithoutGIL release; output = plan->search(query, index->tiles, true); }
        auto result = PyTuple_New(output.size());
        if (!result) return nullptr;
        for (std::size_t i = 0; i < output.size(); ++i) {
            auto item = write(output[i], *plan->ring);
            if (!item) { Py_DECREF(result); return nullptr; }
            PyTuple_SET_ITEM(result, i, item);
        }
        return result;
    });
}
PyObject* sizes(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject* obj;
        if (!PyArg_ParseTuple(args, "O", &obj)) return nullptr;
        auto p = get<Plan>(obj, plan_name);
        return Py_BuildValue("(nn)", Py_ssize_t(p->shared_h_bytes()), Py_ssize_t(p->pair_digit_bytes()));
    });
}
PyMethodDef methods[] = {
    {"create_server", create, METH_VARARGS, "Prepare immutable public Q120 plan."},
    {"prepare_index", prepare, METH_VARARGS, "Prepare bounded canonical index."},
    {"search", search, METH_VARARGS, "Complete public evaluator, no admission."},
    {"state_sizes", sizes, METH_VARARGS, "Exact H and pair-digit word bodies."},
    {nullptr, nullptr, 0, nullptr}
};
PyModuleDef module = {PyModuleDef_HEAD_INIT, "_bgv_propagated", "Isolated public propagation prototype", -1, methods, nullptr, nullptr, nullptr, nullptr};
}
PyMODINIT_FUNC PyInit__bgv_propagated() { return PyModule_Create(&module); }
