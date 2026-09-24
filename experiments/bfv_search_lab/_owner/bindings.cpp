// Separate PRIVATE research extension. The public server does not import it.
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "owner.h"

namespace {
using namespace cuhepy_bgv_owner;
using Handle = std::shared_ptr<Product>;
constexpr const char* name = "cuhepy.lab.bgv.private.product.v1";
struct PythonError {};
struct WithoutGIL {
    PyThreadState* state = PyEval_SaveThread();
    ~WithoutGIL() { PyEval_RestoreThread(state); }
};
template<class F> PyObject* checked(F&& function) {
    try { return function(); }
    catch (const PythonError&) { return nullptr; }
    catch (const std::bad_alloc&) { return PyErr_NoMemory(); }
    catch (const std::invalid_argument& e) { PyErr_SetString(PyExc_ValueError,e.what()); }
    catch (const std::exception& e) { PyErr_SetString(PyExc_RuntimeError,e.what()); }
    return nullptr;
}
Handle get(PyObject* object) {
    auto p = static_cast<Handle*>(PyCapsule_GetPointer(object,name));
    if (!p) throw PythonError{};
    return *p;
}
std::size_t integer(PyObject* object, std::size_t maximum) {
    if (!PyLong_CheckExact(object)) throw std::invalid_argument("Expected integer owner parameter");
    auto value = PyLong_AsSize_t(object);
    if (PyErr_Occurred()) throw PythonError{};
    if (value > maximum) throw std::invalid_argument("Oversized owner parameter");
    return value;
}
std::string_view bytes(PyObject* object) {
    if (!PyBytes_CheckExact(object)) throw std::invalid_argument("Expected immutable owner bytes");
    return {PyBytes_AS_STRING(object),static_cast<std::size_t>(PyBytes_GET_SIZE(object))};
}
mpz_class modulus(PyObject* object) {
    if (!PyUnicode_CheckExact(object)) throw std::invalid_argument("Expected owner modulus hex");
    Py_ssize_t size;
    const char* data = PyUnicode_AsUTF8AndSize(object,&size);
    if (!data) throw PythonError{};
    if (size < 1 || size > 60 || data[0] == '0' || !std::all_of(data,data+size,[](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    })) throw std::invalid_argument("Invalid owner modulus hex");
    mpz_class q;
    q.set_str(data,16);
    if (q < 3) throw std::invalid_argument("Invalid owner modulus");
    return q;
}
void destroy(PyObject* object) { delete static_cast<Handle*>(PyCapsule_GetPointer(object,name)); }
PyObject* create(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *n, *secret;
        if (!PyArg_ParseTuple(args,"OO",&n,&secret)) return nullptr;
        auto result = std::make_unique<Handle>(std::make_shared<Product>(integer(n,32768),bytes(secret)));
        auto capsule = PyCapsule_New(result.get(),name,destroy);
        if (capsule) result.release();
        return capsule;
    });
}
PyObject* prepare(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *object, *q;
        if (!PyArg_ParseTuple(args,"OO",&object,&q)) return nullptr;
        auto owner = get(object); auto mod = modulus(q);
        { WithoutGIL release; owner->prepare(mod); }
        Py_RETURN_NONE;
    });
}
PyObject* multiply(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *object, *poly, *q;
        if (!PyArg_ParseTuple(args,"OOO",&object,&poly,&q)) return nullptr;
        auto owner = get(object); auto input = bytes(poly); auto mod = modulus(q);
        std::string result;
        { WithoutGIL release; result = owner->multiply(input,mod); }
        return PyBytes_FromStringAndSize(result.data(),result.size());
    });
}
PyObject* encrypt(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *object, *a, *message, *entropy, *q, *t, *eta;
        if (!PyArg_ParseTuple(args,"OOOOOOO",&object,&a,&message,&entropy,&q,&t,&eta)) return nullptr;
        auto owner = get(object); auto av = bytes(a), mv = bytes(message), ev = bytes(entropy);
        auto mod = modulus(q); auto plaintext = integer(t,(1U<<30)-1), noise = integer(eta,64);
        std::string result;
        { WithoutGIL release; result = owner->encrypt(av,mv,ev,mod,plaintext,noise); }
        return PyBytes_FromStringAndSize(result.data(),result.size());
    });
}
PyObject* decrypt(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *object, *c0, *c1, *q, *t;
        if (!PyArg_ParseTuple(args,"OOOOO",&object,&c0,&c1,&q,&t)) return nullptr;
        auto owner = get(object); auto a = bytes(c0), b = bytes(c1);
        auto mod = modulus(q); auto plaintext = integer(t,(1U<<30)-1);
        std::string result;
        { WithoutGIL release; result = owner->decrypt(a,b,mod,plaintext); }
        return PyBytes_FromStringAndSize(result.data(),result.size());
    });
}
PyObject* close(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject* object;
        if (!PyArg_ParseTuple(args,"O",&object)) return nullptr;
        auto owner = get(object);
        { WithoutGIL release; owner->close(); }
        Py_RETURN_NONE;
    });
}
PyMethodDef methods[] = {
    {"create",create,METH_VARARGS,"Create a private ternary multiplication cache."},
    {"prepare",prepare,METH_VARARGS,"Prepare the public coefficient width."},
    {"multiply",multiply,METH_VARARGS,"Local private ternary multiplication."},
    {"encrypt",encrypt,METH_VARARGS,"Create c0 from caller-supplied fresh independent entropy."},
    {"decrypt",decrypt,METH_VARARGS,"Local unauthenticated fixture decryption; not a protocol."},
    {"close",close,METH_VARARGS,"Close the private owner; no secure-erasure guarantee."},
    {nullptr,nullptr,0,nullptr}
};
PyModuleDef module = {PyModuleDef_HEAD_INIT,"_bgv_owner","Private variable-time BGV research arithmetic.",-1,
                     methods,nullptr,nullptr,nullptr,nullptr};
}
PyMODINIT_FUNC PyInit__bgv_owner() { return PyModule_Create(&module); }
