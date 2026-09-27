#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "check.h"
#include "product.h"

namespace {
using Context=std::shared_ptr<const cuhepy_bgv_check::Arithmetic>;
using Product=std::shared_ptr<const cuhepy_bgv_check::ProductArithmetic>;
constexpr const char* tag="cuhepy.lab.bgv.check.arithmetic.v1";
constexpr const char* product_tag="cuhepy.lab.bgv.product.arithmetic.v1";
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
Product get_product(PyObject* obj) {
    auto ptr=static_cast<Product*>(PyCapsule_GetPointer(obj,product_tag));if(!ptr) throw PythonError{};return *ptr;
}
void destroy_product(PyObject* obj) { delete static_cast<Product*>(PyCapsule_GetPointer(obj,product_tag)); }
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
PyObject* product_create(PyObject*,PyObject* args) {
    return checked([&]()->PyObject* {
        PyObject *c,*input,*count;if(!PyArg_ParseTuple(args,"OOO",&c,&input,&count)) return nullptr;
        auto ctx=get(c);auto raw=bytes(input);auto b=integer(count,64);Product product;
        { WithoutGIL release;product=std::make_shared<cuhepy_bgv_check::ProductArithmetic>(std::move(ctx),raw,b); }
        auto result=std::make_unique<Product>(std::move(product));
        auto obj=PyCapsule_New(result.get(),product_tag,destroy_product);if(obj) result.release();return obj;
    });
}
PyObject* product_validate(PyObject*,PyObject* args) {
    return checked([&]()->PyObject* {
        PyObject *c,*witness,*output,*mode;if(!PyArg_ParseTuple(args,"OOOO",&c,&witness,&output,&mode)) return nullptr;
        auto ctx=get_product(c);auto w=bytes(witness),out=bytes(output);auto local=integer(mode,1);
        {WithoutGIL release;ctx->validate(w,out,local);}Py_RETURN_NONE;
    });
}
PyObject* product_evaluate(PyObject*,PyObject* args) {
    return checked([&]()->PyObject* {
        PyObject *c,*input,*include;if(!PyArg_ParseTuple(args,"OOO",&c,&input,&include)) return nullptr;
        auto ctx=get_product(c);auto in=bytes(input);auto witness=integer(include,1);
        std::pair<std::string,std::string> result;
        {WithoutGIL release;result=ctx->evaluate(in,witness);}
        return Py_BuildValue("(y#y#)",result.first.data(),static_cast<Py_ssize_t>(result.first.size()),
                             result.second.data(),static_cast<Py_ssize_t>(result.second.size()));
    });
}
PyObject* product_check(PyObject*,PyObject* args) {
    return checked([&]()->PyObject* {
        PyObject *c,*input,*witness,*output,*weights,*mode;
        if(!PyArg_ParseTuple(args,"OOOOOO",&c,&input,&witness,&output,&weights,&mode)) return nullptr;
        auto ctx=get_product(c);auto in=bytes(input),w=bytes(witness),out=bytes(output),a=bytes(weights);auto local=integer(mode,1);
        bool accepted;{WithoutGIL release;accepted=ctx->check(in,w,out,a,local);}
        return PyBool_FromLong(accepted);
    });
}
PyMethodDef methods[]={{"create",create,METH_VARARGS,nullptr},{"validate",validate,METH_VARARGS,nullptr},
                      {"check_arithmetic",verify,METH_VARARGS,nullptr},{"primes",primes,METH_O,nullptr},
                      {"product_create",product_create,METH_VARARGS,nullptr},{"product_validate",product_validate,METH_VARARGS,nullptr},
                      {"product_evaluate",product_evaluate,METH_VARARGS,nullptr},{"product_check",product_check,METH_VARARGS,nullptr},
                      {nullptr,nullptr,0,nullptr}};
PyModuleDef module={PyModuleDef_HEAD_INIT,"_bgv_checked",nullptr,-1,methods,nullptr,nullptr,nullptr,nullptr};
}
PyMODINIT_FUNC PyInit__bgv_checked(){return PyModule_Create(&module);}
