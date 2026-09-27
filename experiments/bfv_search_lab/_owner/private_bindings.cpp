// Separate BGV private terminal kernel; all ciphertexts are validated before secret work.
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "bgv_private.h"

namespace {
using Decoder = cuhepy_bgv_private::Decoder;
using Word = cuhepy_bgv_private::Word;
using Handle = std::shared_ptr<Decoder>;
constexpr const char* capsule_name = "cuhepy.bgv.private.decoder.v1";
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
    if (!PyLong_CheckExact(object)) throw std::invalid_argument("Private BGV parameters must be integers");
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
std::vector<Word> read_component(PyObject* object, const Decoder& decoder, bool packed) {
    const std::size_t n = decoder.degree();
    const Word p = decoder.modulus();
    unsigned bits = 0;
    for (Word v = p; v; v >>= 1) ++bits;
    const std::size_t length = packed ? n * bits / 8 : 8 * n;
    if (!PyBytes_CheckExact(object) || PyBytes_GET_SIZE(object) != static_cast<Py_ssize_t>(length))
        throw std::invalid_argument("Incorrect fixed-width private ciphertext length");
    const auto* bytes = reinterpret_cast<const unsigned char*>(PyBytes_AS_STRING(object));
    std::vector<Word> result(n);
    xtrace_bfv_private::Wide accumulator = 0;
    unsigned available = 0;
    std::size_t at = 0;
    for (std::size_t i = 0; i < result.size(); ++i) {
        Word value = 0;
        if (packed) {
            while (available < bits) {
                accumulator |= xtrace_bfv_private::Wide(bytes[at++]) << available;
                available += 8;
            }
            value = Word(accumulator) & ((Word(1) << bits) - 1);
            accumulator >>= bits;
            available -= bits;
        } else {
            for (unsigned j = 0; j < 8; ++j) value |= Word(bytes[8 * i + j]) << (8 * j);
        }
        if (value >= p) throw std::invalid_argument("Noncanonical private ciphertext coefficient");
        result[i] = value;
    }
    return result;
}
PyObject* decode_impl(PyObject* args, bool packed) {
    return checked([&]() -> PyObject* {
        PyObject *context, *pairs;
        if (!PyArg_ParseTuple(args, "OO", &context, &pairs)) return nullptr;
        auto decoder = handle(context);
        if (!PyTuple_CheckExact(pairs) || PyTuple_GET_SIZE(pairs) < 1 || PyTuple_GET_SIZE(pairs) > 64)
            throw std::invalid_argument("Expected 1..64 BGV ciphertext pairs");
        std::vector<std::pair<std::vector<Word>, std::vector<Word>>> inputs;
        for (Py_ssize_t j = 0; j < PyTuple_GET_SIZE(pairs); ++j) {
            PyObject* pair = PyTuple_GET_ITEM(pairs, j);
            if (!PyTuple_CheckExact(pair) || PyTuple_GET_SIZE(pair) != 2)
                throw std::invalid_argument("Expected two BGV components");
            inputs.emplace_back(read_component(PyTuple_GET_ITEM(pair, 0), *decoder, packed),
                                read_component(PyTuple_GET_ITEM(pair, 1), *decoder, packed));
        }
        // Validate EVERY coefficient of EVERY ciphertext before the first private product.
        // Allocation is fixed by public dimensions; plaintext export is the scope boundary.
        PyObject* output = PyBytes_FromStringAndSize(nullptr, 4 * decoder->degree() * inputs.size());
        if (!output) return nullptr;
        try {
            { WithoutGIL release;
              auto bytes = reinterpret_cast<unsigned char*>(PyBytes_AS_STRING(output));
              for (std::size_t j = 0; j < inputs.size(); ++j)
                  decoder->decode(inputs[j].first.data(), inputs[j].second.data(),
                                  bytes + 4 * decoder->degree() * j); }
        } catch (...) {
            // Clear any partial plaintext before handing its allocation back to Python.
            auto bytes = reinterpret_cast<volatile unsigned char*>(PyBytes_AS_STRING(output));
            for (Py_ssize_t i = 0; i < PyBytes_GET_SIZE(output); ++i) bytes[i] = 0;
            Py_DECREF(output); throw;
        }
        return output;
    });
}
PyObject* decode(PyObject*, PyObject* args) { return decode_impl(args, false); }
PyObject* decode_packed(PyObject*, PyObject* args) { return decode_impl(args, true); }
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
    {"decode_many", decode, METH_VARARGS, "Decode two canonical terminal components into fixed-width coefficients."},
    {"decode_packed_many", decode_packed, METH_VARARGS, "Validate ALL bit-packed components before private decoding."},
    {"close_decoder", close, METH_O, "Wipe a decoder and reject subsequent private operations."},
    {nullptr, nullptr, 0, nullptr}
};
PyModuleDef module = {PyModuleDef_HEAD_INIT, "_bgv_private", "Fixed-work BGV terminal decryption.", -1, methods, nullptr, nullptr, nullptr, nullptr};
}
PyMODINIT_FUNC PyInit__bgv_private() {
    PyObject* result = PyModule_Create(&module);
    if (!result) return nullptr;
    if (PyModule_AddIntConstant(result, "ABI_VERSION", 1) < 0) { Py_DECREF(result); return nullptr; }
    return result;
}
