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
    if (PyUnicode_GET_LENGTH(object) < 1 || PyUnicode_GET_LENGTH(object) > 60)
        throw std::invalid_argument("Invalid owner modulus hex length");
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
        PyObject *n, *secret, *rns = Py_False;
        if (!PyArg_ParseTuple(args,"OO|O",&n,&secret,&rns)) return nullptr;
        if (!PyBool_Check(rns)) throw std::invalid_argument("Private RNS mode must be bool");
        auto result = std::make_unique<Handle>(std::make_shared<Product>(integer(n,32768),bytes(secret),rns == Py_True));
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
PyObject* result_bytes(const std::pair<std::string,std::string>& result) {
    return Py_BuildValue("(y#y#)",result.first.data(),static_cast<Py_ssize_t>(result.first.size()),
                         result.second.data(),static_cast<Py_ssize_t>(result.second.size()));
}
PyObject* finish(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *object, *pairs, *q, *t, *count, *dimension, *k, *all;
        if (!PyArg_ParseTuple(args,"OOOOOOOO",&object,&pairs,&q,&t,&count,&dimension,&k,&all)) return nullptr;
        auto owner = get(object); auto mod = modulus(q);
        auto plain = integer(t,(1U<<30)-1), rows = integer(count,64*owner->n);
        auto d = integer(dimension,owner->n/2), top = integer(k,64);
        if (!PyBool_Check(all) || !PyTuple_CheckExact(pairs) ||
            PyTuple_GET_SIZE(pairs) != static_cast<Py_ssize_t>((rows+owner->n-1)/owner->n))
            throw std::invalid_argument("Invalid native result fields");
        std::vector<std::array<std::string_view,2>> input;
        for (Py_ssize_t i = 0; i < PyTuple_GET_SIZE(pairs); ++i) {
            auto pair = PyTuple_GET_ITEM(pairs,i);
            if (!PyTuple_CheckExact(pair) || PyTuple_GET_SIZE(pair) != 2)
                throw std::invalid_argument("Expected native result component pair");
            input.push_back({bytes(PyTuple_GET_ITEM(pair,0)),bytes(PyTuple_GET_ITEM(pair,1))});
        }
        std::pair<std::string,std::string> result;
        { WithoutGIL release; result = owner->finish(input,mod,plain,rows,d,top,all == Py_True); }
        return result_bytes(result);
    });
}
// Plaintext-only oracle boundary for the same decoder, including invalid padding.
PyObject* finish_plaintexts(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *polys, *n, *t, *count, *dimension, *k, *all;
        if (!PyArg_ParseTuple(args,"OOOOOOO",&polys,&n,&t,&count,&dimension,&k,&all)) return nullptr;
        auto degree = integer(n,32768), plain = integer(t,(1U<<30)-1), rows = integer(count,64*degree);
        auto d = integer(dimension,degree/2), top = integer(k,64);
        if (!PyBool_Check(all) || !PyTuple_CheckExact(polys)) throw std::invalid_argument("Invalid native plaintext result fields");
        Finisher finisher(degree,plain,rows,d,top,all == Py_True);
        if (PyTuple_GET_SIZE(polys) != static_cast<Py_ssize_t>(finisher.groups()))
            throw std::invalid_argument("Invalid native plaintext result count");
        std::vector<std::string_view> input;
        for (Py_ssize_t i = 0; i < PyTuple_GET_SIZE(polys); ++i) {
            auto poly = bytes(PyTuple_GET_ITEM(polys,i));
            if (poly.size() != degree*4) throw std::invalid_argument("Invalid native plaintext byte count");
            input.push_back(poly);
        }
        std::pair<std::string,std::string> result;
        { WithoutGIL release;
          for (auto poly : input) {
              std::vector<Word> values(degree);
              for (std::size_t i = 0; i < degree; ++i) values[i] = load_word(poly,4*i)&0xffffffffU;
              finisher.consume(values);
          }
          result = finisher.result(); }
        return result_bytes(result);
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
    {"finish",finish,METH_VARARGS,"Local decryption, exact distance decoding and stable top-k."},
    {"finish_plaintexts",finish_plaintexts,METH_VARARGS,"Plaintext-only decoder oracle; no secret key required."},
    {"close",close,METH_VARARGS,"Close the private owner; no secure-erasure guarantee."},
    {nullptr,nullptr,0,nullptr}
};
PyModuleDef module = {PyModuleDef_HEAD_INIT,"_bgv_owner","Private variable-time BGV research arithmetic.",-1,
                     methods,nullptr,nullptr,nullptr,nullptr};
}
PyMODINIT_FUNC PyInit__bgv_owner() { return PyModule_Create(&module); }
