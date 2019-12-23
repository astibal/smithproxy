/*
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
*/

#ifndef PYINSPECTOR_HPP
#define PYINSPECTOR_HPP

#include <lockable.hpp>
#include <policy/inspectors.hpp>

#ifdef USE_PYTHON

#define PY_SSIZE_T_CLEAN
#include <Python.h>

class py_module_err : public std::exception {
public:
    const char* what() const noexcept override {
        return "python module loading error";
    }
};

class PythonFactory : public lockable {

    using PythonLock = locked_guard<PythonFactory>;

    PythonFactory() :
        py_modules("python modules", 0, false),
        py_update("python update()s", 0, false),
        py_store("python store()s", 0, false)
        {
        locked_guard<PythonFactory> l(this);
        Py_Initialize();
    }

    ptr_cache<std::string, PyObject> py_modules;
    ptr_cache<std::string, PyObject> py_update;
    ptr_cache<std::string, PyObject> py_store;

    logan_lite log = logan_lite("python");
public:

    static PythonFactory& instance() {
        static PythonFactory p;
        return p;
    }

    PyObject* module_get(std::string const& py_name) {
        PythonLock l(this);
        return py_modules.get(py_name);
    };

    int module_add(std::string const& path) {
        auto* _ = module_get(path);
        if(! _) {

            PythonLock l(this);

            PyObject *pName = PyUnicode_DecodeFSDefault(path.c_str());
            PyObject *pModule = PyImport_Import(pName);
            Py_DECREF(pName);

            int ret = 0;
            PyObject* pFunc_update = nullptr;
            PyObject* pFunc_store = nullptr;

            if(pModule) {
                // continue https://docs.python.org/3.7/extending/embedding.html

                pFunc_update = PyObject_GetAttrString(pModule, "update");
                if(pFunc_update) {
                    if( ! PyCallable_Check(pFunc_update)) {
                        Py_DECREF(pFunc_update);
                        pFunc_update = nullptr;
                    } else {
                        py_update.set(path, pFunc_update);
                        ret++;
                    }
                }

                pFunc_store = PyObject_GetAttrString(pModule, "store");
                if(pFunc_store && PyCallable_Check(pFunc_store)) {
                    if( ! PyCallable_Check(pFunc_store)) {
                        Py_DECREF(pFunc_store);
                        pFunc_store = nullptr;
                    } else {
                        py_store.set(path, pFunc_store);
                        ret++;
                    }
                }

                py_modules.set(path, pModule);
                return ret;
            }
        }

        return -1;
    }
};

typedef locked_guard<PythonFactory> PythonLock;

class PythonInspector : public Inspector {
public:

    PythonInspector() = default;

    void update (AppHostCX *cx) override {
        auto& py = PythonFactory::instance();
        PythonLock l(py);

        // do stuff
    }

    bool l4_prefilter (AppHostCX *cx) override {
        return true;
    }

    bool interested (AppHostCX *cx) const override {
        return true;
    }
};

#endif // USE_PYTHON
#endif //PYINSPECTOR_HPP
