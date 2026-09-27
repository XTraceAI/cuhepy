#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "check.h"

namespace {
using Context=std::shared_ptr<const cuhepy_bgv_check::Arithmetic>;
constexpr const char* tag="cuhepy.lab.bgv.check.arithmetic.v1";
struct PythonError {};
struct WithoutGIL { PyThreadState* saved=PyEval_SaveThread();~WithoutGIL(){PyEval_RestoreThread(saved);} };
template<class F> PyObject* checked(F&& fn) {
    try { return fn(); }
    catch(const PythonError&) { return nullptr; }
    catch(const std::bad_alloc&) { return PyErr_NoMemory(); }
    catch(const std::invalid_argument& e) { PyErr_SetString(PyExc_ValueError,e.what()); }
    catch(const std::exception& e) { PyErr_SetString(PyExc_RuntimeError,e.what()); }
    return nullptr;
}
std::size_t integer(PyObject* obj,std::size_t max) {
    if(!PyLong_CheckExact(obj)) throw std::invalid_argument("Expected exact bounded integer");
    auto n=PyLong_AsSize_t(obj);if(PyErr_Occurred()) throw PythonError{};
    if(n>max) throw std::invalid_argument("Oversized check parameter");
    return n;
}
std::string_view bytes(PyObject* obj) {
    if(!PyBytes_CheckExact(obj)) throw std::invalid_argument("Expected immutable check bytes");
    return {PyBytes_AS_STRING(obj),std::size_t(PyBytes_GET_SIZE(obj))};
}
Context get(PyObject* obj) {
    auto ptr=static_cast<Context*>(PyCapsule_GetPointer(obj,tag));if(!ptr) throw PythonError{};return *ptr;
}
void destroy(PyObject* obj) { delete static_cast<Context*>(PyCapsule_GetPointer(obj,tag)); }
PyObject* create(PyObject*,PyObject* args) {
    return checked([&]()->PyObject* {
        PyObject *n,*key;if(!PyArg_ParseTuple(args,"OO",&n,&key)) return nullptr;
        auto size=integer(n,16384);auto raw=bytes(key);Context ctx;
        { WithoutGIL release;ctx=std::make_shared<cuhepy_bgv_check::Arithmetic>(size,raw); }
        auto result=std::make_unique<Context>(std::move(ctx));
        auto obj=PyCapsule_New(result.get(),tag,destroy);if(obj) result.release();return obj;
    });
}
PyObject* validate(PyObject*,PyObject* args) {
    return checked([&]()->PyObject* {
        PyObject *c,*input,*batch,*parts;
        if(!PyArg_ParseTuple(args,"OOOO",&c,&input,&batch,&parts)) return nullptr;
        auto ctx=get(c);auto raw=bytes(input);auto b=integer(batch,64),k=integer(parts,3);
        { WithoutGIL release;ctx->validate(raw,b,k); }Py_RETURN_NONE;
    });
}
PyObject* primes(PyObject*,PyObject* arg) {
    return checked([&]()->PyObject* {
        auto ctx=get(arg);
        return Py_BuildValue("(KK)",static_cast<unsigned long long>(ctx->primes[0]),
                             static_cast<unsigned long long>(ctx->primes[1]));
    });
}
PyObject* verify(PyObject*,PyObject* args) {
    return checked([&]()->PyObject* {
        PyObject *c,*input,*output,*weights,*batch;
        if(!PyArg_ParseTuple(args,"OOOOO",&c,&input,&output,&weights,&batch)) return nullptr;
        auto ctx=get(c);auto in=bytes(input),out=bytes(output),w=bytes(weights);auto b=integer(batch,64);
        bool accepted;{WithoutGIL release;accepted=ctx->check(in,out,w,b);}
        return PyBool_FromLong(accepted);
    });
}
PyMethodDef methods[]={{"create",create,METH_VARARGS,nullptr},{"validate",validate,METH_VARARGS,nullptr},
                      {"check_arithmetic",verify,METH_VARARGS,nullptr},{"primes",primes,METH_O,nullptr},
                      {nullptr,nullptr,0,nullptr}};
PyModuleDef module={PyModuleDef_HEAD_INIT,"_bgv_checked",nullptr,-1,methods,nullptr,nullptr,nullptr,nullptr};
}
PyMODINIT_FUNC PyInit__bgv_checked(){return PyModule_Create(&module);}
