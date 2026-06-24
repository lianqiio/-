/**
 * 主程：：页面初始化、按钮事件绑定、业务流程编排、设备恢复授权
 */

var globalEnvSafe = true;

// ==================== 阅后即焚 ====================
var burnTimerId = null;
var burnSecondsLeft = 30;
var BURN_TOTAL = 30;
/** 倒计时 */
function startBurnTimer() {
    stopBurnTimer();

    burnSecondsLeft = BURN_TOTAL;
    var burnPanel   = document.getElementById('burn-timer');
    var countdownEl = document.getElementById('burn-countdown');
    var progressFill = document.getElementById('burn-progress-fill');

    if (burnPanel) { burnPanel.style.display = 'block'; }
    if (countdownEl) {
        countdownEl.textContent = burnSecondsLeft;
        countdownEl.classList.remove('urgent');
    }
    if (progressFill) {
        progressFill.style.width = '100%';
        progressFill.classList.remove('urgent');
    }

    burnTimerId = setInterval(function () {
        burnSecondsLeft--;
        if (countdownEl) {
            countdownEl.textContent = burnSecondsLeft;
        }
        if (progressFill) {
            progressFill.style.width = (burnSecondsLeft / BURN_TOTAL) * 100 + '%';
        }

        // 最后 10 秒进入紧急闪烁状态
        if (burnSecondsLeft <= 10 && burnSecondsLeft > 0) {
            if (countdownEl)   { countdownEl.classList.add('urgent'); }
            if (progressFill)   { progressFill.classList.add('urgent'); }
        }

        // 归零 → 销毁
        if (burnSecondsLeft <= 0) {
            stopBurnTimer();
            var outputArea = document.getElementById('plain-output');
            if (outputArea) { outputArea.value = ''; }
            if (burnPanel)  { burnPanel.style.display = 'none'; }
            logEvent('阅后即焚：明文已被自动销毁', 'warning');
        }
    }, 1000);
}

/** 停止阅后即焚倒计时 */
function stopBurnTimer() {
    if (burnTimerId !== null) {
        clearInterval(burnTimerId);
        burnTimerId = null;
    }
    var burnPanel = document.getElementById('burn-timer');
    if (burnPanel) { burnPanel.style.display = 'none'; }
}

document.addEventListener('DOMContentLoaded', async function () {

    // ==================== DOM 元素引用 ====================
    var envStatus   = document.getElementById('env-status');
    var fpBrowser   = document.getElementById('fp-browser');
    var fpScreen    = document.getElementById('fp-screen');
    var fpHASH      = document.getElementById('fp-hash');
    var recoveryGroup = document.getElementById('recovery-decrypt-group');
    var recoveryHint  = document.getElementById('recovery-hint');

    // ==================== 页面初始化 ====================
    logEvent('初始化零信任安全核心...', 'system');

    // 显示设备指纹信息
    var fpInfo = getFingerprintInfo();
    fpBrowser.textContent = fpInfo.browser.substring(0, 45) + '...';
    fpScreen.textContent  = fpInfo.screen;

    var hashVal = await getFingerprintHash();
    fpHASH.textContent = hashVal.substring(0, 36) + '...';
    logEvent('设备指纹采集完成 (SHA-256)', 'info');

    // 零信任环境校验
    globalEnvSafe = await checkEnvironment();

    if (globalEnvSafe) {
        envStatus.textContent = '✓ 环境安全 - 已通过零信任校验';
        envStatus.className = 'status-badge safe';
        logEvent('零信任环境校验通过，设备认证成功', 'success');
    } else {
        envStatus.textContent = '✗ 设备未注册或不在信任列表中';
        envStatus.className = 'status-badge danger';
        logEvent('零信任警报：当前环境校验未通过，可能需要恢复密钥', 'warning');
        // 自动显示恢复密钥输入框（首次使用设备在执行加密后会自动隐藏）
        if (recoveryGroup) { recoveryGroup.style.display = 'block'; }
    }

    // ==================== 加密按钮 ====================
    document.getElementById('btn-encrypt').addEventListener('click', async function () {
        var plainText  = document.getElementById('plain-text').value.trim();
        var password   = document.getElementById('encrypt-pwd').value;
        var recPwd     = document.getElementById('encrypt-recovery-pwd').value;
        var outputArea = document.getElementById('cipher-output');

        if (!plainText) { alert('请输入要加密的机密内容！'); return; }
        if (!password)  { alert('请设置主控密码！'); return; }

        // 首次使用（无已注册设备）自动登记，设备不匹配则拒绝
        var isSafe = await checkEnvironment();
        if (!isSafe) {
            var storedHash = localStorage.getItem('zero_trust_vault_fingerprint');
            if (storedHash === null || storedHash === '') {
                // 首次使用：注册当前设备为初始受信任设备
                await registerCurrentDevice();
                globalEnvSafe = true;
                envStatus.textContent = '✓ 环境安全 - 设备已注册';
                envStatus.className = 'status-badge safe';
                if (recoveryGroup) { recoveryGroup.style.display = 'none'; }
                logEvent('首次加密操作，当前设备已注册为受信任设备', 'success');
            } else {
                // 设备不匹配：拒绝加密
                envStatus.textContent = '✗ 环境风险 - 拒绝访问';
                envStatus.className = 'status-badge danger';
                globalEnvSafe = false;
                logEvent('加密操作被门禁系统拦截：环境指纹不匹配', 'danger');
                alert('环境风险！加密操作被拒绝。请在受信任设备上执行。');
                return;
            }
        }

        try {
            var hasRecovery = recPwd && recPwd.trim() !== '';
            logEvent('开始执行 AES-GCM 高强度加密' + (hasRecovery ? ' (含恢复密钥)' : '') + '...', 'info');

            var cipherText = await encryptData(plainText, password, recPwd);
            outputArea.value = cipherText;

            if (hasRecovery) {
                logEvent('数据加密成功！密文已生成，恢复密钥已内嵌于密文中', 'success');
                if (recoveryHint) {
                    recoveryHint.style.display = 'block';
                }
            } else {
                logEvent('数据加密成功！密文已生成 (长度: ' + cipherText.length + ' 字符)', 'success');
                if (recoveryHint) {
                    recoveryHint.style.display = 'none';
                }
            }
        } catch (err) {
            logEvent('加密失败：' + err.message, 'danger');
            alert('加密失败：' + err.message);
        }
    });

    // ==================== 解密按钮 ====================
    document.getElementById('btn-decrypt').addEventListener('click', async function () {
        stopBurnTimer(); // 新解密操作，取消旧倒计时

        var cipherText = document.getElementById('cipher-input').value.trim();
        var password   = document.getElementById('decrypt-pwd').value;
        var recPwd     = document.getElementById('decrypt-recovery-pwd').value;
        var outputArea = document.getElementById('plain-output');

        if (!cipherText) { alert('请贴入待解密的密文！'); return; }
        if (!password)   { alert('请输入主控密码进行身份验证！'); return; }

        // 检查环境状态
        var isSafe = await checkEnvironment();

        if (!isSafe) {
            // 环境不匹配 → 检查密文是否包含恢复数据
            var hasRecoveryData = cipherText.indexOf('::') !== -1;

            if (!hasRecoveryData) {
                envStatus.textContent = '✗ 环境风险 - 无法恢复';
                envStatus.className = 'status-badge danger';
                globalEnvSafe = false;
                logEvent('解密被拒：密文不包含恢复数据，无法在未授权设备上解密', 'danger');
                outputArea.value = '⚠ 此密文在加密时未设置恢复密钥，无法在当前设备解密。请在原始设备上操作。';
                return;
            }

            // 有恢复数据，检查用户是否输入了恢复密钥
            if (!recPwd || recPwd.trim() === '') {
                envStatus.textContent = '✗ 环境风险 - 请填写恢复密钥';
                envStatus.className = 'status-badge danger';
                globalEnvSafe = false;
                if (recoveryGroup) { recoveryGroup.style.display = 'block'; }
                logEvent('设备未授权！请在下方输入恢复密钥后重试', 'danger');
                outputArea.value = '⚠ 当前设备不在信任列表中，请填写恢复密钥后重新解密。';
                return;
            }
            logEvent('当前设备未授权，尝试使用恢复密钥解密...', 'info');
        } else {
            logEvent('环境校验通过，开始解密...', 'info');
        }

        try {
            var plainText = await decryptData(cipherText, password, recPwd);
            outputArea.value = plainText;

            // 启动阅后即焚倒计时
            startBurnTimer();
            logEvent('明文已显示，30 秒后自动销毁。请尽快截图或复制', 'info');

            // 如果是恢复模式解密成功，自动将当前设备加入信任列表
            if (!isSafe && recPwd && recPwd.trim() !== '') {
                try {
                    await trustCurrentDevice();
                    globalEnvSafe = true;
                    envStatus.textContent = '✓ 环境安全 - 设备已通过恢复授权';
                    envStatus.className = 'status-badge safe';
                    if (recoveryGroup) { recoveryGroup.style.display = 'none'; }
                    logEvent('恢复解密成功！当前设备已被授权加入信任列表，后续无需恢复密钥', 'success');
                } catch (trustErr) {
                    logEvent('恢复解密成功，但自动授权设备失败（可能是存储空间不足）', 'warning');
                }
            } else {
                logEvent('身份验证通过，数据成功提取', 'success');
            }
        } catch (err) {
            logEvent('解密失败：' + err.message, 'danger');
            outputArea.value = '';
            alert(err.message);
        }
    });

    // ==================== 模拟攻击按钮 ====================
    document.getElementById('btn-simulate-attack').addEventListener('click', function () {
        logEvent('用户触发了模拟黑客攻击演练', 'info');
        simulateAttack();
    });

    // ==================== 清空日志按钮 ====================
    document.getElementById('btn-clear-log').addEventListener('click', function () {
        clearLogDisplay();
    });

    // ==================== 明文复制检测 ====================
    var plainOutput = document.getElementById('plain-output');
    plainOutput.addEventListener('copy', function () {
        logEvent('⚠ 明文已被复制到剪贴板！请注意信息安全', 'warning');
    });

    logEvent('所有安全模块加载完毕，系统就绪', 'success');
});
