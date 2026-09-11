// Optional, separate private decoder extension. The public server ABI is unchanged.
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "private_decoder.h"

namespace {
using Decoder = xtrace_bfv_private::PrivateDecoder;
using Word = xtrace_bfv_private::Word;
using Handle = std::shared_ptr<Decoder>;
constexpr const char* capsule_name = "xtrace.bfv.private.decoder.v1";
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
Word integer(PyObject* object) {
    if (!PyLong_CheckExact(object)) throw std::invalid_argument("Private BFV parameters must be integers");
    Word value = PyLong_AsUnsignedLongLong(object);
    if (PyErr_Occurred()) throw PythonError{};
    return value;
}
Handle handle(PyObject* object) {
    auto result = static_cast<Handle*>(PyCapsule_GetPointer(object, capsule_name));
    if (!result) throw PythonError{};
    return *result;
}
void destroy(PyObject* capsule) {
    delete static_cast<Handle*>(PyCapsule_GetPointer(capsule, capsule_name));
}
PyObject* create(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *n_arg, *q_arg, *t_arg, *p0_arg, *p1_arg, *secret;
        if (!PyArg_ParseTuple(args, "OOOOOO", &n_arg, &q_arg, &t_arg, &p0_arg, &p1_arg, &secret)) return nullptr;
        Word n = integer(n_arg), q = integer(q_arg), t = integer(t_arg), p0 = integer(p0_arg), p1 = integer(p1_arg);
        if (n > 32768 || !PyBytes_CheckExact(secret) || PyBytes_GET_SIZE(secret) != static_cast<Py_ssize_t>(n))
            throw std::invalid_argument("Incorrect fixed-width private key length");
        Handle decoder;
        { WithoutGIL release;
          decoder = std::make_shared<Decoder>(n, q, t, p0, p1,
              reinterpret_cast<const unsigned char*>(PyBytes_AS_STRING(secret))); }
        auto owner = std::make_unique<Handle>(std::move(decoder));
        PyObject* result = PyCapsule_New(owner.get(), capsule_name, destroy);
        if (result) owner.release();
        return result;
    });
}
std::vector<Word> read_component(PyObject* object, const Decoder& decoder) {
    if (!PyBytes_CheckExact(object) || PyBytes_GET_SIZE(object) != static_cast<Py_ssize_t>(8 * decoder.degree()))
        throw std::invalid_argument("Incorrect fixed-width private ciphertext length");
    const auto* bytes = reinterpret_cast<const unsigned char*>(PyBytes_AS_STRING(object));
    std::vector<Word> result(decoder.degree());
    for (std::size_t i = 0; i < result.size(); ++i) {
        Word value = 0;
        for (unsigned j = 0; j < 8; ++j) value |= Word(bytes[8 * i + j]) << (8 * j);
        if (value >= decoder.modulus()) throw std::invalid_argument("Noncanonical private ciphertext coefficient");
        result[i] = value;
    }
    return result;
}
PyObject* decode(PyObject*, PyObject* args) {
    return checked([&]() -> PyObject* {
        PyObject *context, *left, *right;
        if (!PyArg_ParseTuple(args, "OOO", &context, &left, &right)) return nullptr;
        auto decoder = handle(context);
        auto c0 = read_component(left, *decoder), c1 = read_component(right, *decoder);
        PyObject* output = PyBytes_FromStringAndSize(nullptr, 4 * decoder->degree());
        if (!output) return nullptr;
        try {
            { WithoutGIL release;
              decoder->decode(c0.data(), c1.data(), reinterpret_cast<unsigned char*>(PyBytes_AS_STRING(output))); }
        } catch (...) { Py_DECREF(output); throw; }
        return output;
    });
}
PyObject* close(PyObject*, PyObject* context) {
    return checked([&]() -> PyObject* {
        auto decoder = handle(context);
        // Waiting for an in-flight decoder must not hold the GIL it needs to return.
        { WithoutGIL release; decoder->close(); }
        Py_RETURN_NONE;
    });
}
PyMethodDef methods[] = {
    {"create_decoder", create, METH_VARARGS, "Import a bounded ternary key into locked native buffers."},
    {"decode_slots", decode, METH_VARARGS, "Decode two canonical terminal components into fixed-width slots."},
    {"close_decoder", close, METH_O, "Wipe a decoder and reject subsequent private operations."},
    {nullptr, nullptr, 0, nullptr}
};
PyModuleDef module = {PyModuleDef_HEAD_INIT, "_bfv_private", "Fixed-work BFV terminal decryption.", -1, methods, nullptr, nullptr, nullptr, nullptr};
}
PyMODINIT_FUNC PyInit__bfv_private() {
    PyObject* result = PyModule_Create(&module);
    if (!result) return nullptr;
    if (PyModule_AddIntConstant(result, "ABI_VERSION", 1) < 0) { Py_DECREF(result); return nullptr; }
    return result;
}
