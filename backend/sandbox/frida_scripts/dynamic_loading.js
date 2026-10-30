// ============================================================
// Frida hook: Dynamic code loading
//
// Monitors:
//   - DexClassLoader
//   - PathClassLoader
//   - BaseDexClassLoader.findClass
//   - Class.forName
//   - Method.invoke
//   - Constructor.newInstance
//   - System.loadLibrary
//   - System.load
//   - Runtime.loadLibrary
//   - Runtime.load
// ============================================================

Java.perform(function () {

    function stackTrace() {
        try {
            var Log = Java.use("android.util.Log");
            var Exception = Java.use("java.lang.Exception");

            return Log.getStackTraceString(
                Exception.$new()
            ).substring(0, 1500);

        } catch (e) {
            return "stack unavailable: " + e;
        }
    }


    function emit(api, args) {

        send({
            group: "dynamic_loading",
            api: api,
            args: args || {},
            stack: stackTrace()
        });
    }


    // ========================================================
    // DexClassLoader
    // ========================================================

    try {

        var DexClassLoader =
            Java.use("dalvik.system.DexClassLoader");

        var dexInit =
            DexClassLoader.$init.overload(
                "java.lang.String",
                "java.lang.String",
                "java.lang.String",
                "java.lang.ClassLoader"
            );

        dexInit.implementation = function (
            dexPath,
            optimizedDirectory,
            librarySearchPath,
            parent
        ) {

            emit("DexClassLoader.<init>", {
                dexPath: String(dexPath),
                optimizedDirectory: String(optimizedDirectory),
                librarySearchPath: String(librarySearchPath)
            });

            return dexInit.call(
                this,
                dexPath,
                optimizedDirectory,
                librarySearchPath,
                parent
            );
        };

        var dexLoadClass =
            DexClassLoader.loadClass.overload(
                "java.lang.String"
            );

        dexLoadClass.implementation = function (name) {

            emit("DexClassLoader.loadClass", {
                className: String(name)
            });

            return dexLoadClass.call(
                this,
                name
            );
        };

        console.log("[+] DexClassLoader hooks installed");

    } catch (e) {

        send({
            group: "dynamic_loading",
            api: "DexClassLoader_error",
            args: {
                error: String(e)
            }
        });
    }


    // ========================================================
    // PathClassLoader
    // ========================================================

    try {

        var PathClassLoader =
            Java.use("dalvik.system.PathClassLoader");

        var pathInit =
            PathClassLoader.$init.overload(
                "java.lang.String",
                "java.lang.ClassLoader"
            );

        pathInit.implementation = function (
            dexPath,
            parent
        ) {

            emit("PathClassLoader.<init>", {
                dexPath: String(dexPath)
            });

            return pathInit.call(
                this,
                dexPath,
                parent
            );
        };

        console.log("[+] PathClassLoader hooks installed");

    } catch (e) {

        send({
            group: "dynamic_loading",
            api: "PathClassLoader_error",
            args: {
                error: String(e)
            }
        });
    }


    // ========================================================
    // BaseDexClassLoader.findClass
    // ========================================================

    try {

        var BaseDexClassLoader =
            Java.use("dalvik.system.BaseDexClassLoader");

        var findClass =
            BaseDexClassLoader.findClass.overload(
                "java.lang.String"
            );

        findClass.implementation = function (name) {

            emit("BaseDexClassLoader.findClass", {
                className: String(name)
            });

            return findClass.call(
                this,
                name
            );
        };

        console.log("[+] BaseDexClassLoader hook installed");

    } catch (e) {

        send({
            group: "dynamic_loading",
            api: "BaseDexClassLoader_error",
            args: {
                error: String(e)
            }
        });
    }


    // ========================================================
    // Class.forName(String)
    // ========================================================

    try {

        var Class =
            Java.use("java.lang.Class");

        var forName =
            Class.forName.overload(
                "java.lang.String"
            );

        forName.implementation = function (name) {

            emit("Class.forName", {
                className: String(name)
            });

            return forName.call(
                this,
                name
            );
        };


        // Class.forName(String, boolean, ClassLoader)

        var forName3 =
            Class.forName.overload(
                "java.lang.String",
                "boolean",
                "java.lang.ClassLoader"
            );

        forName3.implementation = function (
            name,
            initialize,
            loader
        ) {

            emit(
                "Class.forName(String,boolean,ClassLoader)",
                {
                    className: String(name),
                    initialize: Boolean(initialize)
                }
            );

            return forName3.call(
                this,
                name,
                initialize,
                loader
            );
        };

        console.log("[+] Class.forName hooks installed");

    } catch (e) {

        send({
            group: "dynamic_loading",
            api: "Class.forName_error",
            args: {
                error: String(e)
            }
        });
    }


    // ========================================================
    // Method.invoke
    // ========================================================

    try {

        var Method =
            Java.use("java.lang.reflect.Method");

        var invoke =
            Method.invoke.overload(
                "java.lang.Object",
                "[Ljava.lang.Object;"
            );

        invoke.implementation = function (
            obj,
            args
        ) {

            var methodName = "unknown";
            var declaringClass = "unknown";

            try {
                methodName = this.getName();
                declaringClass =
                    this.getDeclaringClass().getName();
            } catch (e) {}

            emit("Method.invoke", {
                methodName: String(methodName),
                declaringClass: String(declaringClass),
                argCount: args ? args.length : 0
            });

            return invoke.call(
                this,
                obj,
                args
            );
        };

        console.log("[+] Method.invoke hook installed");

    } catch (e) {

        send({
            group: "dynamic_loading",
            api: "Method.invoke_error",
            args: {
                error: String(e)
            }
        });
    }


    // ========================================================
    // Constructor.newInstance
    // ========================================================

    try {

        var Constructor =
            Java.use("java.lang.reflect.Constructor");

        var newInstance =
            Constructor.newInstance.overload(
                "[Ljava.lang.Object;"
            );

        newInstance.implementation = function (
            args
        ) {

            var declaringClass = "unknown";

            try {
                declaringClass =
                    this.getDeclaringClass().getName();
            } catch (e) {}

            emit("Constructor.newInstance", {
                declaringClass: String(declaringClass),
                argCount: args ? args.length : 0
            });

            return newInstance.call(
                this,
                args
            );
        };

        console.log(
            "[+] Constructor.newInstance hook installed"
        );

    } catch (e) {

        send({
            group: "dynamic_loading",
            api: "Constructor.newInstance_error",
            args: {
                error: String(e)
            }
        });
    }


    // ========================================================
    // System.loadLibrary
    // ========================================================

    try {

        var System =
            Java.use("java.lang.System");

        var loadLibrary =
            System.loadLibrary.overload(
                "java.lang.String"
            );

        loadLibrary.implementation = function (
            libName
        ) {

            emit("System.loadLibrary", {
                libraryName: String(libName)
            });

            return loadLibrary.call(
                this,
                libName
            );
        };


        var load =
            System.load.overload(
                "java.lang.String"
            );

        load.implementation = function (
            path
        ) {

            emit("System.load", {
                libraryPath: String(path)
            });

            return load.call(
                this,
                path
            );
        };

        console.log("[+] System native-load hooks installed");

    } catch (e) {

        send({
            group: "dynamic_loading",
            api: "System_load_error",
            args: {
                error: String(e)
            }
        });
    }


    // ========================================================
    // Runtime.loadLibrary / Runtime.load
    // ========================================================

    try {

        var Runtime =
            Java.use("java.lang.Runtime");


        var runtimeLoadLibrary =
            Runtime.loadLibrary.overload(
                "java.lang.String"
            );

        runtimeLoadLibrary.implementation = function (
            libName
        ) {

            emit("Runtime.loadLibrary", {
                libraryName: String(libName)
            });

            return runtimeLoadLibrary.call(
                this,
                libName
            );
        };


        var runtimeLoad =
            Runtime.load.overload(
                "java.lang.String"
            );

        runtimeLoad.implementation = function (
            path
        ) {

            emit("Runtime.load", {
                libraryPath: String(path)
            });

            return runtimeLoad.call(
                this,
                path
            );
        };

        console.log(
            "[+] Runtime native-load hooks installed"
        );

    } catch (e) {

        send({
            group: "dynamic_loading",
            api: "Runtime_load_error",
            args: {
                error: String(e)
            }
        });
    }


    // ========================================================
    // Ready
    // ========================================================

    send({
        group: "dynamic_loading",
        api: "HOOKS_READY",
        args: {
            message: "Dynamic loading hooks installed successfully"
        }
    });

});