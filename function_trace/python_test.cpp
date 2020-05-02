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
    std::cout << "module imported" << std::endl;

    PyObject *dict = PyModule_GetDict(module);
    if (dict == nullptr) {
        PyErr_Print();
        std::cerr << "Fails to get the dictionary.\n";
        return 1;
    }
    Py_DECREF(module);
    std::cout << "module dictionary found" << std::endl;

    PyObject *python_class = PyDict_GetItemString(dict, "TraceCollector");
    if (python_class == nullptr) {
        PyErr_Print();
        std::cerr << "Fails to get the Python class.\n";
        return 1;
    }
    Py_DECREF(dict);
    std::cout << "class found" << std::endl;


    // Creates an instance of the class
    PyObject *py_trace_obj = nullptr;
    if (PyCallable_Check(python_class)) {
        PyObject *args = Py_BuildValue("(s)", "~/go-repro/909_ziptest/ziptest ~/go-repro/909_ziptest/test.zip");
        PyObject *keywords = PyDict_New();
        PyDict_SetItemString(keywords, "is_32", Py_True);
        PyDict_SetItemString(keywords, "pin", PyUnicode_FromString("~/pin-3.11/pin"));

        py_trace_obj = PyObject_Call(python_class, args, keywords);
        Py_DECREF(python_class);
        Py_DECREF(args);
        Py_DECREF(keywords);
    } else {
        std::cerr << "Python class not callable" << std::endl;
        Py_DECREF(python_class);
        return 1;
    }

    if (py_trace_obj == nullptr) {
        std::cerr << "Fails to instantiate Python class" << std::endl;
        return 1;
    }
    std::cout << "class instantiated" << std::endl;

    PyObject_CallMethod(py_trace_obj, "run_function_trace", "(s)", "scanblock");
    PyObject_CallMethod(py_trace_obj, "read_trace_from_disk", "(s)", "scanblock");
    PyObject *is_before = PyObject_CallMethod(py_trace_obj, "is_instruction_after", "(s,s)", "0x80500bb", "0x80500bf");

    if (is_before == nullptr) {
        PyErr_Print();
        std::cerr << "Failed to get function result" << std::endl;
        return 1;
    }

    if (PyObject_IsTrue(is_before)) {
        std::cout << "Is before" << std::endl;
    } else {
        std::cout << "Not before" << std::endl;
    }
    

    Py_Finalize();
    return 0;
}