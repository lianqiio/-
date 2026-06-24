/**
 * 审计日志系统 
 * 全局日志记录系统，所有加密、解密、登录行为实时输出到界面底部的审计控制台，
 * 每条日志带精确时间戳。以及模拟攻击演示按钮（暂时纯前端实现）。
 */

/**
 * 记录一条带时间戳的审计日志到界面控制台
 * @param {string} message  - 日志内容
 * @param {string} type     - 日志级别: 'system' | 'info' | 'success' | 'danger' | 'warning'
 */
function logEvent(message, type) {
    if (!type) { type = 'system'; }

    var now = new Date();
    var timeStr = now.getHours().toString().padStart(2, '0') + ':'
                + now.getMinutes().toString().padStart(2, '0') + ':'
                + now.getSeconds().toString().padStart(2, '0');

    var logBox = document.getElementById('audit-log');
    if (!logBox) { return; }

    var entryEl = document.createElement('p');
    entryEl.className = 'log-entry ' + type;
    entryEl.innerHTML = '<span class="time">[' + timeStr + ']</span> ' + escapeText(message);

    logBox.appendChild(entryEl);
    logBox.scrollTop = logBox.scrollHeight;
}

/** 简单 HTML 转义，防止日志注入 XSS */
function escapeText(str) {
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 *模拟黑客攻击，向日志中连续刷入警告，演示熔断保护机制被激活时的审计效果（仅演示设想效果，无实际攻击）。
 */
function simulateAttack() {
    var attackMessages = [
        '检测到异常连接请求！来源不明！',
        '检测到异常数据修改！已触发保险柜熔断机制',
        '未授权访问企图被拦截！IP已加入黑名单',
        '暴力破解行为检测！账户已临时冻结',
        '数据完整性校验失败！密文可能遭篡改',
        '中间人攻击特征出现！通信通道已切断',
        '异常流量模式！正在进行深度包检测',
        '会话劫持尝试！当前会话已被终止',
        '未经授权的解密请求！操作已被阻止',
    ];

    var i = 0;
    var timer = setInterval(function () {
        logEvent(attackMessages[i], 'danger');
        i++;
        if (i >= attackMessages.length) {
            clearInterval(timer);
            logEvent('模拟攻击结束。熔断保护机制运行正常，所有异常已拦截。', 'success');
        }
    }, 350);
}

/** 清空审计日志面板 */
function clearLogDisplay() {
    var logBox = document.getElementById('audit-log');
    if (logBox) {
        logBox.innerHTML = '';
        logEvent('审计日志已被手动清空', 'system');
    }
}
