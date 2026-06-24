/**
 * 加密算法引擎(Crypto Engine)
 * AES-GCM (带认证的加密)+PBKDF2(防暴力破解的密钥派生)
 * 调用浏览器原生Web Crypto API
 */

// 文本编码器与解码器（用于字符串与字节流之间的转换）
const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * 密钥派生函数 (Key Derivation Function)
 * PBKDF2算法，让浏览器计算100,000次，把简单的字符串变成256位的随机密钥。
 */
async function deriveKey(password, salt) {
    // 1. 将字符串密码转换为基础密钥材料
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
    // 2. 结合随机盐进行十万次哈希迭代，生成AES-GCM256位密钥
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// 辅助工具：ArrayBuffer 转 Base64 字符串（方便在网页文本框里展示和复制）
function bufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

// 辅助工具：Base64 字符串转 ArrayBuffer
function base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * 执行高强度封存 (加密)
 * @param {string} plainText        - 要加密的明文
 * @param {string} password         - 用户输入的主密码
 * @param {string} recoveryPassword - (可选) 恢复密钥，用于跨设备解密
 * @returns {Promise<string>} - Base64 密文；若提供了恢复密钥则末尾附"::恢复数据"
 */
async function encryptData(plainText, password, recoveryPassword) {
    try {
        // 1. 生成 16字节随机盐 (Salt) 和 12字节初始化向量 (IV)
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // 1.5 获取设备绑定哈希，与随机盐拼接为复合盐
        const deviceHash = await getDeviceBindingHash();
        const deviceBytes = new Uint8Array(deviceHash);
        const combinedSalt = new Uint8Array(deviceBytes.length + salt.length);
        combinedSalt.set(deviceBytes, 0);
        combinedSalt.set(salt, deviceBytes.length);

        // 2. 派生设备绑定的加密钥匙
        const key = await deriveKey(password, combinedSalt);

        // 3. 执行 AES-GCM 加密
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            enc.encode(plainText)
        );

        // 4. 打包：随机盐 + IV + 密文
        const encryptedBytes = new Uint8Array(encryptedBuffer);
        const bundle = new Uint8Array(salt.length + iv.length + encryptedBytes.length);
        bundle.set(salt, 0);
        bundle.set(iv, salt.length);
        bundle.set(encryptedBytes, salt.length + iv.length);

        var normalPart = bufferToBase64(bundle);

        // 5. 如果提供了恢复密钥，把设备特征码用恢复密钥加密后附在密文尾部
        if (recoveryPassword && recoveryPassword.trim() !== '') {
            var recoverySalt = window.crypto.getRandomValues(new Uint8Array(16));
            var recoveryIV   = window.crypto.getRandomValues(new Uint8Array(12));
            var recoveryKey  = await deriveKey(recoveryPassword, recoverySalt);
            var encDeviceHash = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: recoveryIV },
                recoveryKey,
                deviceBytes
            );
            var recoveryBundle = new Uint8Array(
                recoverySalt.length + recoveryIV.length + encDeviceHash.byteLength
            );
            recoveryBundle.set(recoverySalt, 0);
            recoveryBundle.set(recoveryIV, recoverySalt.length);
            recoveryBundle.set(new Uint8Array(encDeviceHash), recoverySalt.length + recoveryIV.length);

            // 格式：正常密文 + "::" + 恢复数据
            return normalPart + '::' + bufferToBase64(recoveryBundle);
        }

        return normalPart;
    } catch (error) {
        console.error("加密核心崩溃:", error);
        throw new Error("加密过程发生致命错误");
    }
}

// ---- 内部辅助：用当前设备的特征码做正常解密 ----
async function _normalDecrypt(mainPartBase64, password) {
    var bundle = new Uint8Array(base64ToBuffer(mainPartBase64));
    var salt = bundle.slice(0, 16);
    var iv   = bundle.slice(16, 28);
    var encryptedBytes = bundle.slice(28);

    var deviceHash = await getDeviceBindingHash();
    var deviceBytes = new Uint8Array(deviceHash);
    var combinedSalt = new Uint8Array(deviceBytes.length + salt.length);
    combinedSalt.set(deviceBytes, 0);
    combinedSalt.set(salt, deviceBytes.length);

    var key = await deriveKey(password, combinedSalt);
    var decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encryptedBytes
    );
    return dec.decode(decryptedBuffer);
}

// ---- 内部辅助：用恢复密钥 + 密文中附带的加密设备特征码做恢复解密 ----
async function _recoveryDecrypt(mainPartBase64, recoveryPartBase64, password, recoveryPassword) {
    var bundle = new Uint8Array(base64ToBuffer(mainPartBase64));
    var salt = bundle.slice(0, 16);
    var iv   = bundle.slice(16, 28);
    var encryptedBytes = bundle.slice(28);

    // 解析恢复数据：恢复盐 + 恢复IV + 加密的设备特征码
    var recoveryBundle = new Uint8Array(base64ToBuffer(recoveryPartBase64));
    var recoverySalt = recoveryBundle.slice(0, 16);
    var recoveryIV   = recoveryBundle.slice(16, 28);
    var encDeviceHash = recoveryBundle.slice(28);

    // 用恢复密码解密，取出【原始设备】的特征码
    var recoveryKey = await deriveKey(recoveryPassword, recoverySalt);
    var originalDeviceHash = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: recoveryIV },
        recoveryKey,
        encDeviceHash
    );

    // 用原始设备的特征码 + 密码重建密钥
    var originalDeviceBytes = new Uint8Array(originalDeviceHash);
    var combinedSalt = new Uint8Array(originalDeviceBytes.length + salt.length);
    combinedSalt.set(originalDeviceBytes, 0);
    combinedSalt.set(salt, originalDeviceBytes.length);

    var key = await deriveKey(password, combinedSalt);
    var decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encryptedBytes
    );
    return dec.decode(decryptedBuffer);
}

/**
 * 提取数据 (解密)
 * 先尝试用当前设备指纹正常解密；失败后若提供了恢复密钥则尝试恢复模式。
 * @param {string} cipherTextBase64 - Base64 密文串
 * @param {string} password         - 主密码
 * @param {string} recoveryPassword - (可选) 恢复密钥，换设备解密时使用
 * @returns {Promise<string>} - 解密后的明文
 */
async function decryptData(cipherTextBase64, password, recoveryPassword) {
    var parts = cipherTextBase64.split('::');
    var mainPart = parts[0];
    var hasRecovery = parts.length > 1;

    // 先尝试正常设备绑定解密
    try {
        return await _normalDecrypt(mainPart, password);
    } catch (normalError) {
        // 正常解密失败 → 如果有恢复数据且提供了恢复密钥，尝试恢复
        if (hasRecovery && recoveryPassword && recoveryPassword.trim() !== '') {
            try {
                return await _recoveryDecrypt(mainPart, parts[1], password, recoveryPassword);
            } catch (recoveryError) {
                console.error("恢复解密失败:", recoveryError);
                throw new Error("解密失败！密码错误，或恢复密钥错误，或数据包遭到恶意篡改！");
            }
        }
        console.error("解密或防篡改校验失败:", normalError);
        throw new Error("解密失败！密码错误，或数据包遭到恶意篡改，或设备环境已变更！");
    }
}