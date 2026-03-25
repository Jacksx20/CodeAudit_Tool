// CodeAudit Web - JavaScript应用

// 全局变量
let currentTaskId = null;
let currentTargetPath = null;

// 初始化
document.addEventListener('DOMContentLoaded', function() {
    initUpload();
    checkLLMStatus();
    loadHistory();
});

// 检查大模型状态
async function checkLLMStatus() {
    const statusText = document.getElementById('llmStatusText');
    const llmCheckbox = document.getElementById('enableLlm');
    
    // 大模型现在是可选配置,不需要检查状态
    statusText.textContent = '可选配置';
    statusText.style.color = '#3b82f6';
    llmCheckbox.checked = false;
    
    // 添加大模型配置显示/隐藏逻辑
    llmCheckbox.addEventListener('change', function() {
        const configSection = document.getElementById('llmConfigSection');
        if (this.checked) {
            configSection.style.display = 'block';
        } else {
            configSection.style.display = 'none';
        }
    });
    
    // 添加模型选择逻辑
    const modelSelect = document.getElementById('modelName');
    const customModelGroup = document.getElementById('customModelGroup');
    
    modelSelect.addEventListener('change', function() {
        if (this.value === 'custom') {
            customModelGroup.style.display = 'block';
        } else {
            customModelGroup.style.display = 'none';
        }
    });
}

// 初始化上传功能
function initUpload() {
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    const startBtn = document.getElementById('startAuditBtn');
    
    // 拖拽上传
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });
    
    // 点击上传
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });
    
    // 开始审计
    startBtn.addEventListener('click', startAudit);
}

// 处理文件
async function handleFile(file) {
    const startBtn = document.getElementById('startAuditBtn');
    const uploadPlaceholder = document.querySelector('.upload-placeholder');
    
    // 显示文件名
    uploadPlaceholder.innerHTML = `
        <i class="fas fa-file-code" style="color: #10b981;"></i>
        <p><strong>${file.name}</strong></p>
        <p style="font-size: 14px; color: #94a3b8;">${formatFileSize(file.size)}</p>
    `;
    
    // 上传文件
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        showProgress('正在上传文件...');
        
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        currentTaskId = data.task_id;
        currentTargetPath = data.target_path;
        
        // 显示文件信息
        displayFileInfo(data.file_stats);
        
        // 启用审计按钮
        startBtn.disabled = false;
        
        hideProgress();
        
    } catch (error) {
        hideProgress();
        alert('文件上传失败: ' + error.message);
        console.error(error);
    }
}

// 显示文件信息
function displayFileInfo(stats) {
    const section = document.getElementById('fileInfoSection');
    const container = document.getElementById('fileStats');
    
    section.style.display = 'block';
    
    container.innerHTML = `
        <div class="stat-item">
            <div class="stat-label">总文件数</div>
            <div class="stat-value">${stats.total_files}</div>
        </div>
        <div class="stat-item">
            <div class="stat-label">总大小</div>
            <div class="stat-value">${formatFileSize(stats.total_size)}</div>
        </div>
        <div class="stat-item">
            <div class="stat-label">文件类型</div>
            <div class="stat-value">${Object.keys(stats.by_extension).length}</div>
        </div>
    `;
}

// 开始审计
async function startAudit() {
    if (!currentTaskId || !currentTargetPath) {
        alert('请先上传文件');
        return;
    }
    
    const enableLlm = document.getElementById('enableLlm').checked;
    
    // 如果启用大模型,验证配置
    if (enableLlm) {
        const apiKey = document.getElementById('apiKey').value.trim();
        if (!apiKey) {
            alert('请输入API Key');
            return;
        }
    }
    
    const options = {
        enable_llm: enableLlm,
        enable_forward: document.getElementById('enableForward').checked,
        enable_reverse: document.getElementById('enableReverse').checked,
        enable_attack_chain: document.getElementById('enableAttackChain').checked,
        generate_report: true
    };
    
    // 如果启用大模型,添加配置信息
    if (enableLlm) {
        const modelSelect = document.getElementById('modelName');
        let modelName = modelSelect.value;
        
        // 如果选择自定义模型,使用自定义输入的值
        if (modelName === 'custom') {
            modelName = document.getElementById('customModel').value.trim();
            if (!modelName) {
                alert('请输入自定义模型名称');
                return;
            }
        }
        
        options.llm_config = {
            api_key: document.getElementById('apiKey').value.trim(),
            base_url: document.getElementById('apiBaseUrl').value.trim(),
            model: modelName
        };
    }
    
    try {
        showProgress('正在进行安全审计...');
        updateProgress(10, '识别HTTP入口点...');
        
        const response = await fetch('/api/audit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                task_id: currentTaskId,
                target_path: currentTargetPath,
                options: options
            })
        });
        
        const result = await response.json();
        
        if (result.error) {
            throw new Error(result.error);
        }
        
        updateProgress(100, '审计完成');
        
        setTimeout(() => {
            hideProgress();
            displayResult(result);
            loadHistory();
        }, 500);
        
    } catch (error) {
        hideProgress();
        alert('审计失败: ' + error.message);
        console.error(error);
    }
}

// 显示结果
function displayResult(result) {
    const section = document.getElementById('resultSection');
    section.style.display = 'block';
    section.classList.add('fade-in');
    
    const auditResult = result.audit_result;
    const summary = auditResult.summary;
    
    // 显示摘要卡片
    displaySummary(summary, auditResult);
    
    // 显示漏洞列表
    displayVulnerabilities(auditResult.vulnerabilities);
    
    // 显示大模型分析
    if (result.llm_analysis) {
        displayLLMAnalysis(result.llm_analysis);
    }
    
    // 显示攻击链
    if (auditResult.attack_chains && auditResult.attack_chains.length > 0) {
        displayAttackChains(auditResult.attack_chains);
    }
    
    // 设置报告下载
    setupReportDownloads(result.reports);
}

// 显示摘要
function displaySummary(summary, auditResult) {
    const container = document.getElementById('summaryCards');
    
    container.innerHTML = `
        <div class="summary-card critical">
            <h4>Critical 漏洞</h4>
            <div class="value">${summary.critical}</div>
        </div>
        <div class="summary-card high">
            <h4>High 漏洞</h4>
            <div class="value">${summary.high}</div>
        </div>
        <div class="summary-card medium">
            <h4>Medium 漏洞</h4>
            <div class="value">${summary.medium}</div>
        </div>
        <div class="summary-card low">
            <h4>Low 漏洞</h4>
            <div class="value">${summary.low}</div>
        </div>
        <div class="summary-card info">
            <h4>Source点</h4>
            <div class="value">${auditResult.sources_found}</div>
        </div>
        <div class="summary-card info">
            <h4>Sink点</h4>
            <div class="value">${auditResult.sinks_found}</div>
        </div>
        <div class="summary-card info">
            <h4>扫描文件</h4>
            <div class="value">${auditResult.scanned_files}/${auditResult.total_files}</div>
        </div>
        <div class="summary-card info">
            <h4>扫描耗时</h4>
            <div class="value">${auditResult.scan_time.toFixed(2)}s</div>
        </div>
    `;
}

// 显示漏洞列表
function displayVulnerabilities(vulnerabilities) {
    const container = document.getElementById('vulnerabilitiesList');
    
    if (!vulnerabilities || vulnerabilities.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #94a3b8;">未发现漏洞</p>';
        return;
    }
    
    container.innerHTML = vulnerabilities.map((vuln, index) => `
        <div class="vuln-item ${vuln.severity}" data-severity="${vuln.severity}" onclick="showVulnDetail(${index})">
            <div class="vuln-header">
                <div class="vuln-title">${vuln.id}: ${vuln.name}</div>
                <span class="vuln-badge ${vuln.severity}">${vuln.severity}</span>
            </div>
            <div class="vuln-meta">
                <strong>类型:</strong> ${vuln.type} | 
                <strong>CWE:</strong> ${vuln.cwe_id}
            </div>
            <div class="vuln-location">
                <i class="fas fa-map-marker-alt"></i> 
                ${vuln.source.file_path}:${vuln.source.line_number}
            </div>
        </div>
    `).join('');
    
    // 存储漏洞数据用于详情显示
    window.vulnerabilities = vulnerabilities;
    
    // 设置过滤器
    setupFilters();
}

// 设置过滤器
function setupFilters() {
    const filterBtns = document.querySelectorAll('.filter-btn');
    
    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // 更新按钮状态
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // 过滤漏洞
            const filter = btn.dataset.filter;
            const items = document.querySelectorAll('.vuln-item');
            
            items.forEach(item => {
                if (filter === 'all' || item.dataset.severity === filter) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    });
}

// 显示漏洞详情
function showVulnDetail(index) {
    const vuln = window.vulnerabilities[index];
    const modal = document.getElementById('vulnModal');
    const title = document.getElementById('modalTitle');
    const body = document.getElementById('modalBody');
    
    title.textContent = `${vuln.id}: ${vuln.name}`;
    
    let callChainHtml = '';
    if (vuln.call_chain && vuln.call_chain.nodes) {
        callChainHtml = `
            <h4>调用链</h4>
            <div class="call-chain">
                ${vuln.call_chain.nodes.map(node => `
                    <div class="chain-node">
                        <i class="fas fa-arrow-right"></i>
                        <span>${node.function_name}()</span>
                        <small>${node.file_path}:${node.line_number}</small>
                    </div>
                `).join('')}
            </div>
        `;
    }
    
    let pocHtml = '';
    if (vuln.poc_code) {
        pocHtml = `
            <h4>PoC验证代码</h4>
            <pre><code class="language-python">${escapeHtml(vuln.poc_code)}</code></pre>
        `;
    }
    
    body.innerHTML = `
        <div class="vuln-detail">
            <div class="detail-section">
                <h4>基本信息</h4>
                <table class="detail-table">
                    <tr><td>漏洞类型</td><td>${vuln.type}</td></tr>
                    <tr><td>严重程度</td><td><span class="vuln-badge ${vuln.severity}">${vuln.severity}</span></td></tr>
                    <tr><td>CWE编号</td><td>${vuln.cwe_id}</td></tr>
                    <tr><td>描述</td><td>${vuln.description}</td></tr>
                </table>
            </div>
            
            <div class="detail-section">
                <h4>Source点 (入口)</h4>
                <table class="detail-table">
                    <tr><td>文件路径</td><td>${vuln.source.file_path}</td></tr>
                    <tr><td>行号</td><td>${vuln.source.line_number}</td></tr>
                    <tr><td>函数名</td><td>${vuln.source.function_name}()</td></tr>
                    <tr><td>HTTP方法</td><td>${vuln.source.http_method}</td></tr>
                    <tr><td>路由</td><td>${vuln.source.route}</td></tr>
                </table>
            </div>
            
            <div class="detail-section">
                <h4>Sink点 (危险函数)</h4>
                <table class="detail-table">
                    <tr><td>文件路径</td><td>${vuln.sink.file_path}</td></tr>
                    <tr><td>行号</td><td>${vuln.sink.line_number}</td></tr>
                    <tr><td>函数名</td><td>${vuln.sink.function_name}()</td></tr>
                    <tr><td>危险函数</td><td><code>${vuln.sink.dangerous_function}</code></td></tr>
                </table>
            </div>
            
            ${callChainHtml}
            
            <div class="detail-section">
                <h4>修复建议</h4>
                <p>${vuln.remediation}</p>
            </div>
            
            ${pocHtml}
        </div>
    `;
    
    // 高亮代码
    hljs.highlightAll();
    
    modal.classList.add('active');
}

// 关闭模态框
function closeModal() {
    document.getElementById('vulnModal').classList.remove('active');
}

// 显示大模型分析
function displayLLMAnalysis(llmAnalysis) {
    const section = document.getElementById('llmAnalysisSection');
    const content = document.getElementById('llmContent');
    
    if (!llmAnalysis || llmAnalysis.error) {
        return;
    }
    
    section.style.display = 'block';
    
    let html = '';
    
    // 安全总结
    if (llmAnalysis.security_summary) {
        html += `
            <div class="llm-section">
                <h4><i class="fas fa-file-alt"></i> 安全总结</h4>
                <div class="llm-text">${marked.parse(llmAnalysis.security_summary)}</div>
            </div>
        `;
    }
    
    // 风险评估
    if (llmAnalysis.risk_assessment) {
        const risk = llmAnalysis.risk_assessment;
        html += `
            <div class="llm-section">
                <h4><i class="fas fa-exclamation-triangle"></i> 风险评估</h4>
                <table class="detail-table">
                    <tr><td>风险等级</td><td><strong>${risk.risk_level}</strong></td></tr>
                    <tr><td>业务影响</td><td>${risk.business_impact}</td></tr>
                    <tr><td>合规性风险</td><td>${risk.compliance_risk}</td></tr>
                </table>
            </div>
        `;
    }
    
    // 修复建议
    if (llmAnalysis.recommendations && llmAnalysis.recommendations.length > 0) {
        html += `
            <div class="llm-section">
                <h4><i class="fas fa-lightbulb"></i> 修复建议</h4>
                <ul class="recommendations-list">
                    ${llmAnalysis.recommendations.map(rec => `
                        <li>
                            <strong>[${rec.priority}]</strong> ${rec.content}
                            <small>(${rec.effort})</small>
                        </li>
                    `).join('')}
                </ul>
            </div>
        `;
    }
    
    content.innerHTML = html;
}

// 显示攻击链
function displayAttackChains(chains) {
    const section = document.getElementById('attackChainsSection');
    const container = document.getElementById('attackChainsList');
    
    section.style.display = 'block';
    
    container.innerHTML = chains.map((chain, index) => `
        <div class="attack-chain-item">
            <h4>攻击链 #${index + 1}</h4>
            <p><strong>描述:</strong> ${chain.description}</p>
            <p><strong>影响:</strong> ${chain.impact}</p>
            <p><strong>涉及漏洞:</strong> ${chain.vulnerabilities.join(', ')}</p>
        </div>
    `).join('');
}

// 设置报告下载
function setupReportDownloads(reports) {
    if (!reports) return;
    
    document.getElementById('downloadJson').onclick = () => {
        window.location.href = `/api/report/${currentTaskId}/json`;
    };
    
    document.getElementById('downloadHtml').onclick = () => {
        window.location.href = `/api/report/${currentTaskId}/html`;
    };
    
    document.getElementById('downloadMd').onclick = () => {
        window.location.href = `/api/report/${currentTaskId}/markdown`;
    };
}

// 加载历史记录
async function loadHistory() {
    try {
        const response = await fetch('/api/tasks');
        const data = await response.json();
        
        const container = document.getElementById('historyList');
        
        if (!data.tasks || data.tasks.length === 0) {
            container.innerHTML = '<p style="color: #94a3b8; font-size: 14px;">暂无历史记录</p>';
            return;
        }
        
        container.innerHTML = data.tasks.slice(0, 10).map(task => `
            <div class="history-item" onclick="loadTask('${task.task_id}')">
                <div class="history-time">${formatTime(task.start_time)}</div>
                <div class="history-status">
                    ${task.status === 'completed' ? '✅' : '❌'} 
                    ${task.vulnerabilities_count} 个漏洞
                </div>
            </div>
        `).join('');
        
    } catch (error) {
        console.error('加载历史记录失败:', error);
    }
}

// 加载历史任务
async function loadTask(taskId) {
    try {
        const response = await fetch(`/api/result/${taskId}`);
        const result = await response.json();
        
        if (result.error) {
            alert('加载失败: ' + result.error);
            return;
        }
        
        currentTaskId = taskId;
        displayResult(result);
        
    } catch (error) {
        alert('加载失败: ' + error.message);
    }
}

// 显示进度
function showProgress(text) {
    const section = document.getElementById('progressSection');
    const progressText = document.getElementById('progressText');
    
    section.style.display = 'block';
    progressText.textContent = text;
}

// 更新进度
function updateProgress(percent, text) {
    const fill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    
    fill.style.width = percent + '%';
    if (text) {
        progressText.textContent = text;
    }
}

// 隐藏进度
function hideProgress() {
    document.getElementById('progressSection').style.display = 'none';
}

// 工具函数
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatTime(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString('zh-CN', {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// 点击模态框外部关闭
document.getElementById('vulnModal').addEventListener('click', function(e) {
    if (e.target === this) {
        closeModal();
    }
});

// ESC键关闭模态框
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeModal();
    }
});
