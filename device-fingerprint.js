/**
 * 设备指纹生成与校验：基于浏览器特征和屏幕信息生成唯一哈希，
 * 作为"设备基因锁"，确保数据只能在受信任设备上解密。
 * 支持多设备信任列表，允许通过恢复密钥授权新设备。
 */

var FINGERPRINT_STORAGE_KEY   = 'zero_trust_vault_fingerprint';
var TRUSTED_DEVICES_KEY       = 'zero_trust_trusted_devices';

/**
 * 生成当前环境指纹哈希值
 * 将userAgent+屏幕分辨率拼接后做SHA-256哈希
 * @returns {Promise<string>} 64位十六进制哈希字符串
 */
async function generateFingerprint() {
    var raw = navigator.userAgent + '||' + screen.width + 'x' + screen.height;
    var enc = new TextEncoder();
    var hashBuffer = await crypto.subtle.digest('SHA-256', enc.encode(raw));
    var hashArray = Array.from(new Uint8Array(hashBuffer));
    var hashHex = hashArray.map(function (b) {
        return b.toString(16).padStart(2, '0');
    }).join('');
    return hashHex;
}

/**
 * 获取设备指纹原始信息（用于UI面板展示）
 * @returns {{ browser: string, screen: string }}
 */
function getFingerprintInfo() {
    return {
        browser: navigator.userAgent,
        screen: screen.width + ' x ' + screen.height
    };
}

/**
 * 检查当前环境是否安全
 * 只有已注册设备（指纹匹配）或处于信任列表中的设备才视为安全。
 * 首次访问不会自动注册——需通过加密操作显式登记。
 * @returns {Promise<boolean>} true = 环境安全, false = 设备不匹配或未注册
 */
async function checkEnvironment() {
    var currentHash = await generateFingerprint();
    var storedHash = localStorage.getItem(FINGERPRINT_STORAGE_KEY);
    // 没有任何已注册设备 → 环境不可信（不再自动注册！）
    if (storedHash === null || storedHash === '') {
        return false;
    }
    // 初始设备匹配
    if (currentHash === storedHash) {
        return true;
    }
    // 信任列表中的设备匹配（恢复解密后授权的设备）
    var trusted = getTrustedDevices();
    if (trusted.indexOf(currentHash) !== -1) {
        return true;
    }
    return false;
}

/**
 * 获取受信任设备哈希列表
 * @returns {string[]}
 */
function getTrustedDevices() {
    var stored = localStorage.getItem(TRUSTED_DEVICES_KEY);
    if (stored) {
        return JSON.parse(stored);
    }
    return [];
}

/**
 * 将当前设备加入受信任列表（恢复解密成功后自动调用）
 * @returns {Promise<void>}
 */
async function trustCurrentDevice() {
    var currentHash = await generateFingerprint();
    var trusted = getTrustedDevices();

    if (trusted.indexOf(currentHash) === -1) {
        trusted.push(currentHash);
        localStorage.setItem(TRUSTED_DEVICES_KEY, JSON.stringify(trusted));
    }
}

/**
 * 将当前设备注册为初始受信任设备（仅在用户明确执行加密操作时调用）
 * @returns {Promise<void>}
 */
async function registerCurrentDevice() {
    var currentHash = await generateFingerprint();
    localStorage.setItem(FINGERPRINT_STORAGE_KEY, currentHash);
}

/**
 * 获取当前指纹哈希值（用于UI面板展示）
 * @returns {Promise<string>}
 */
async function getFingerprintHash() {
    return await generateFingerprint();
}

/**
 * 【调试用】重置设备绑定，模拟更换设备场景
 */
function resetFingerprint() {
    localStorage.removeItem(FINGERPRINT_STORAGE_KEY);
}
