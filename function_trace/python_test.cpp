#include <iostream>
#include <Python.h>


int main(int argc, char *argv[]) {
    Py_Initialize();

    PyObject *module_name = PyUnicode_FromString("trace");
    PyObject *module = PyImport_Import(module_name);
    if (module == nullptr) {
        PyErr_Print();
        std::cerr << "Fails to import the module.\n";
        return 1;
    }
    Py_DECREF(module_name);

    PyObject *dict = PyModule_GetDict(module);
    if (dict == nullptr) {
        PyErr_Print();
        std::cerr << "Fails to get the dictionary.\n";
        return 1;
    }
    Py_DECREF(module);

    PyObject *python_class = PyDict_GetItemString(dict, "TraceCollector");
    if (python_class == nullptr) {
        PyErr_Print();
        std::cerr << "Fails to get the Python class.\n";
        return 1;
    }
    Py_DECREF(dict);

    PyObject *args = Py_BuildValue("~/go-repro/909_ziptest/ziptest ~/go-repro/909_ziptest/test.zip");
    PyObject *keywords = PyDict_New();
    PyDict_SetItemString(keywords, "is_32", Py_True);
    PyDict_SetItemString(keywords, "pin", PyUnicode_FromString("~/pin-3.11/pin"));

    // Creates an instance of the class
    PyObject *py_trace_obj = nullptr;
    if (PyCallable_Check(python_class)) {
        py_trace_obj = PyObject_Call(python_class, args, keywords);
        Py_DECREF(python_class);
    } else {
        std::cout << "Cannot instantiate the Python class" << std::endl;
        Py_DECREF(python_class);
        return 1;
    }

    Py_Finalize();
    return(0);
}