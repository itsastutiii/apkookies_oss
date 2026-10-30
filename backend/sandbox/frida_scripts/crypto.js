// Frida hook: Cryptographic operations
// Monitors Cipher.doFinal, Cipher.init, and key generation

Java.perform(function () {
    // Cipher.doFinal - payload decryption/encryption
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        var doFinal = Cipher.doFinal.overload('[B');
        doFinal.implementation = function (input) {
            var result = this.doFinal(input);
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "crypto",
                api: "Cipher.doFinal(byte[])",
                args: {
                    algorithm: this.getAlgorithm(),
                    provider: this.getProvider() ? this.getProvider().getName() : "unknown",
                    inputLength: input ? input.length : 0,
                    outputLength: result ? result.length : 0,
                    // Note: we don't log actual plaintext/ciphertext for safety
                    mode: "doFinal"
                },
                stack: stack.substring(0, 500)
            });
            return result;
        };

        var doFinal2 = Cipher.doFinal.overload('[B', 'int', 'int');
        doFinal2.implementation = function (input, offset, len) {
            var result = this.doFinal(input, offset, len);
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "crypto",
                api: "Cipher.doFinal(byte[],int,int)",
                args: {
                    algorithm: this.getAlgorithm(),
                    provider: this.getProvider() ? this.getProvider().getName() : "unknown",
                    inputLength: len,
                    outputLength: result ? result.length : 0,
                    mode: "doFinal"
                },
                stack: stack.substring(0, 500)
            });
            return result;
        };

        var doFinal3 = Cipher.doFinal.overload('[B', 'int', 'int', '[B');
        doFinal3.implementation = function (input, offset, len, output) {
            var result = this.doFinal(input, offset, len, output);
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "crypto",
                api: "Cipher.doFinal(byte[],int,int,byte[])",
                args: {
                    algorithm: this.getAlgorithm(),
                    provider: this.getProvider() ? this.getProvider().getName() : "unknown",
                    inputLength: len,
                    outputLength: result,
                    mode: "doFinal"
                },
                stack: stack.substring(0, 500)
            });
            return result;
        };

        // Cipher.init - capture algorithm/mode/padding and key
        var init = Cipher.init.overload('int', 'java.security.Key');
        init.implementation = function (opmode, key) {
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            var keyInfo = "unknown";
            try {
                keyInfo = key.getAlgorithm() + "/" + key.getFormat();
            } catch (e) {}
            send({
                group: "crypto",
                api: "Cipher.init(int,Key)",
                args: {
                    algorithm: this.getAlgorithm(),
                    provider: this.getProvider() ? this.getProvider().getName() : "unknown",
                    opmode: opmodeToString(opmode),
                    key: keyInfo
                },
                stack: stack.substring(0, 500)
            });
            return this.init(opmode, key);
        };

        var init2 = Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec');
        init2.implementation = function (opmode, key, params) {
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            var keyInfo = "unknown";
            try {
                keyInfo = key.getAlgorithm() + "/" + key.getFormat();
            } catch (e) {}
            var paramInfo = "unknown";
            try {
                paramInfo = params.getClass().getName();
            } catch (e) {}
            send({
                group: "crypto",
                api: "Cipher.init(int,Key,AlgorithmParameterSpec)",
                args: {
                    algorithm: this.getAlgorithm(),
                    provider: this.getProvider() ? this.getProvider().getName() : "unknown",
                    opmode: opmodeToString(opmode),
                    key: keyInfo,
                    params: paramInfo
                },
                stack: stack.substring(0, 500)
            });
            return this.init(opmode, key, params);
        };

    } catch (e) {
        send({group: "crypto", api: "init_error", args: {error: e.toString()}});
    }

    // SecretKeySpec - key material (be careful not to log actual keys)
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        var $init = SecretKeySpec.$init.overload('[B', 'int', 'int', 'java.lang.String');
        $init.implementation = function (key, offset, len, algorithm) {
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "crypto",
                api: "SecretKeySpec.<init>",
                args: {
                    algorithm: algorithm,
                    keyLength: len,
                    // Never log actual key bytes
                    keyHash: arrayHash(key, offset, len).substring(0, 16) // First 16 chars of hash for reference
                },
                stack: stack.substring(0, 500)
            });
            return this.$init(key, offset, len, algorithm);
        };
    } catch (e) {}

    // MessageDigest - hashing
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        var digest = MessageDigest.digest.overload('[B');
        digest.implementation = function (input) {
            var result = this.digest(input);
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "crypto",
                api: "MessageDigest.digest",
                args: {
                    algorithm: this.getAlgorithm(),
                    inputLength: input ? input.length : 0,
                    outputLength: result ? result.length : 0
                },
                stack: stack.substring(0, 500)
            });
            return result;
        };
    } catch (e) {}

    // KeyGenerator - key generation
    try {
        var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        var generateKey = KeyGenerator.generateKey;
        generateKey.implementation = function () {
            var result = this.generateKey();
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "crypto",
                api: "KeyGenerator.generateKey",
                args: {
                    algorithm: this.getAlgorithm(),
                    provider: this.getProvider() ? this.getProvider().getName() : "unknown"
                },
                stack: stack.substring(0, 500)
            });
            return result;
        };
    } catch (e) {}

    function opmodeToString(opmode) {
        var modes = {
            1: "ENCRYPT_MODE",
            2: "DECRYPT_MODE",
            3: "WRAP_MODE",
            4: "UNWRAP_MODE"
        };
        return modes[opmode] || "UNKNOWN(" + opmode + ")";
    }

    function arrayHash(arr, offset, len) {
        // Simple hash for reference (not cryptographic)
        var hash = 0;
        for (var i = offset; i < offset + len && i < arr.length; i++) {
            hash = ((hash << 5) - hash) + arr[i];
            hash = hash & hash;
        }
        return Math.abs(hash).toString(16);
    }
});