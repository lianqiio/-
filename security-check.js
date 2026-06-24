/**
 * 设备绑定模块 (security-check.js)
 * 提取设备多维特征码，生成唯一哈希用作密钥绑定的设备盐。
 * 该哈希会被插入deriveKey的PBKDF2 salt中，使得加密密钥与设备强绑定。
 */

/**
 * 生成设备绑定哈希 (32字节SHA-256ArrayBuffer)
 * 浏览器型号+屏幕分辨率+系统时区
 * @returns {Promise<ArrayBuffer>}
 */
async function getDeviceBindingHash() {
    var browser = navigator.userAgent;
    var screenSize = screen.width + 'x' + screen.height;
    var timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

    var rawString = browser + '|||' + screenSize + '|||' + timeZone;
    var enc = new TextEncoder();
    var hashBuffer = await crypto.subtle.digest('SHA-256', enc.encode(rawString));

    // 返回原始 ArrayBuffer (32字节)
    return hashBuffer;
}
