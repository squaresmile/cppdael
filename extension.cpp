#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "rijndael.h"

typedef struct
{
    PyObject_HEAD
        CRijndael *rj;
    uint8_t mode;
} RijndaelObject;

static int
Rijndael_init(RijndaelObject *self, PyObject *args, PyObject *kwds)
{
    // parse the arguments
    uint8_t mode;
    uint16_t block_size;
    uint16_t key_size;
    char key[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Py_ssize_t key_size_;
    char iv[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Py_ssize_t iv_size;
    // mode, key, iv, key_size, block_size
    if (!PyArg_ParseTuple(args, "bHHy#y#", &mode, &block_size, &key_size, &key, &key_size_, &iv, &iv_size))
        return -1;

    // check input
    if (mode > CRijndael::CFB)
    {
        PyErr_SetString(PyExc_ValueError, "invalid mode (ECB = 0, CBC = 1, CFB = 2)");
        return -1;
    }
    self->mode = mode;
    if (block_size != 16 && block_size != 24 && block_size != 32)
    {
        PyErr_SetString(PyExc_ValueError, "invalid block size");
        return -1;
    }
    if (key_size != 16 && key_size != 24 && key_size != 32)
    {
        PyErr_SetString(PyExc_ValueError, "invalid key size");
        return -1;
    }

    self->rj = new CRijndael;
    self->rj->MakeKey(key, iv, key_size, block_size);
    return 0;
}

static void Rijndael_dealloc(RijndaelObject *self)
{
    delete (self->rj);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
Rijndael_getKeyLength(RijndaelObject *self, void *closure)
{
    return PyLong_FromLong(self->rj->GetKeyLength());
}

static PyObject *
Rijndael_getBlockSize(RijndaelObject *self, void *closure)
{
    return PyLong_FromLong(self->rj->GetBlockSize());
}

static PyObject *
Rijndael_getRounds(RijndaelObject *self, void *closure)
{
    return PyLong_FromLong(self->rj->GetRounds());
}

static PyGetSetDef Rijndael_getsetters[] = {
    {"key_length", (getter)Rijndael_getKeyLength, NULL,
     "length of the key", NULL},
    {"block_size", (getter)Rijndael_getBlockSize, NULL,
     "size of the block", NULL},
    {"rounds", (getter)Rijndael_getRounds, NULL, "number of rounds", NULL},
    {NULL} /* Sentinel */
};

static PyObject *Rijndael_EncryptBlock(RijndaelObject *self, PyObject *args)
{
    char *in;
    Py_ssize_t in_size;
    char *out;

    if (!PyArg_ParseTuple(args, "y#", &in, &in_size))
        return NULL;
    out = (char*)PyMem_Malloc(in_size);
    self->rj->EncryptBlock(in, out);
    PyObject* ret = PyBytes_FromStringAndSize(out, in_size);
    PyMem_Free(out);
    return ret;
}

static PyObject *Rijndael_DecryptBlock(RijndaelObject *self, PyObject *args)
{
    char *in;
    Py_ssize_t in_size;
    char *out;

    if (!PyArg_ParseTuple(args, "y#", &in, &in_size))
        return NULL;
    out = (char*)PyMem_Malloc(in_size);
    self->rj->DecryptBlock(in, out);
    PyObject* ret = PyBytes_FromStringAndSize(out, in_size);
    PyMem_Free(out);
    return ret;
}

static PyObject *Rijndael_Encrypt(RijndaelObject *self, PyObject *args)
{
    char *in;
    Py_ssize_t in_size;
    char *out;

    if (!PyArg_ParseTuple(args, "y#", &in, &in_size))
        return NULL;
    out = (char*)PyMem_Malloc(in_size);
    self->rj->Encrypt(in, out, in_size, self->mode);
    PyObject* ret = PyBytes_FromStringAndSize(out, in_size);
    PyMem_Free(out);
    return ret;
}

static PyObject *Rijndael_Decrypt(RijndaelObject *self, PyObject *args)
{
    char *in;
    Py_ssize_t in_size;
    char *out;

    if (!PyArg_ParseTuple(args, "y#", &in, &in_size))
        return NULL;
    out = (char*)PyMem_Malloc(in_size);
    self->rj->Decrypt(in, out, in_size, self->mode);
    PyObject* ret = PyBytes_FromStringAndSize(out, in_size);
    PyMem_Free(out);
    return ret;
}

static PyMethodDef Rijndael_methods[] = {
    {"encrypt_block", (PyCFunction)Rijndael_EncryptBlock, METH_VARARGS,
     PyDoc_STR("encrypts a block of data")},
    {"decrypt_block", (PyCFunction)Rijndael_DecryptBlock, METH_VARARGS,
     PyDoc_STR("decrypts a block of data")},
    {"encrypt", (PyCFunction)Rijndael_Encrypt, METH_VARARGS,
     PyDoc_STR("encrypts the given data")},
    {"decrypt", (PyCFunction)Rijndael_Decrypt, METH_VARARGS,
     PyDoc_STR("decrypts the given data")},
    {NULL},
};

/*  
############################################################################
    create RijndaelType and module for Python
############################################################################
*/

static PyTypeObject RijndaelType = {
    PyVarObject_HEAD_INIT(NULL, 0) "cppdael.Rijndael",                /* tp_name */
    sizeof(RijndaelObject),                                           /* tp_basicsize */
    0,                                                                /* tp_itemsize */
    (destructor)Rijndael_dealloc,                                     /* tp_dealloc */
    0,                                                                /* tp_vectorcall_offset */
    0,                                                                /* tp_getattr */
    0,                                                                /* tp_setattr */
    0,                                                                /* tp_as_async */
    /*(reprfunc)myobj_repr*/ 0,                                       /* tp_repr */
    0,                                                                /* tp_as_number */
    0,                                                                /* tp_as_sequence */
    0,                                                                /* tp_as_mapping */
    0,                                                                /* tp_hash */
    0,                                                                /* tp_call */
    0,                                                                /* tp_str */
    0,                                                                /* tp_getattro */
    0,                                                                /* tp_setattro */
    0,                                                                /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                                               /* tp_flags */
    "a Rijndael that allows an easy and fast parsing of binary data", /* tp_doc */
    0,                                                                /* tp_traverse */
    0,                                                                /* tp_clear */
    0,                                                                /* tp_richcompare */
    0,                                                                /* tp_weaklistoffset */
    0,                                                                /* tp_iter */
    0,                                                                /* tp_iternext */
    Rijndael_methods,                                                 /* tp_methods */
    0,                                                                /* tp_members */
    Rijndael_getsetters,                                              /* tp_getset */
    0,                                                                /* tp_base */
    0,                                                                /* tp_dict */
    0,                                                                /* tp_descr_get */
    0,                                                                /* tp_descr_set */
    0,                                                                /* tp_dictoffset */
    (initproc)Rijndael_init,                                          /* tp_init */
    0,                                                                /* tp_alloc */
    PyType_GenericNew,                                                /* tp_new */
};

static PyObject* decrypt_string(PyObject *self, PyObject *args)
{
    char* input;
    Py_ssize_t input_size;
    char* key;
    Py_ssize_t key_size;
    char* iv;
    Py_ssize_t iv_size;
    if (!PyArg_ParseTuple(args, "s#s#s#", &input, &input_size, &key, &key_size, &iv, &iv_size))
        return NULL;
    const std::string Input = std::string(input, input_size);
    const std::string Key = std::string(key, key_size);
    const std::string IV = std::string(iv, iv_size);
    std::string ret = decrypt_string(Input, Key, IV);
    return PyBytes_FromStringAndSize(ret.c_str(), ret.length());
}


// Exported methods are collected in a table
static struct PyMethodDef method_table[] = {
    {"decrypt_string",
     (PyCFunction)decrypt_string,
     METH_VARARGS,
     ""
    },
    {NULL,
     NULL,
     0,
     NULL} // Sentinel value ending the table
};


static PyModuleDef cppdael_module = {
    PyModuleDef_HEAD_INIT,
    "cppdael",
    "a Rijndael that allows an easy and fast parsing of binary data",
    -1,
    method_table,
    NULL, // Optional slot definitions
    NULL, // Optional traversal function
    NULL, // Optional clear function
    NULL  // Optional module deallocation function
};

PyMODINIT_FUNC
PyInit_cppdael(void)
{
    PyObject *m;
    if (PyType_Ready(&RijndaelType) < 0)
        return NULL;

    m = PyModule_Create(&cppdael_module);
    if (m == NULL)
        return NULL;

    Py_INCREF(&RijndaelType);
    if (PyModule_AddObject(m, "Rijndael", (PyObject *)&RijndaelType) < 0)
    {
        Py_DECREF(&RijndaelType);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}