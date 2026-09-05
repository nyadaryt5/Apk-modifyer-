/**
 * OmniAPK Studio & AI Suite - Core Web Application JS
 * Handles UI interactions, API calls, real-time WebSockets, and modding orchestrations.
 */

// Global State
let currentApkPath = "";
let currentApksList = [];
let wsConnection = null;

// Initialize on DOM Load
document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initPlatformDiagnostics();
    initWebSocket();
    loadApkList();
    initAutonomousAgent();
    initLuckyPatcher();
    initApktoolM();
    initDecompilerStudio();
    initMtManager();
    initFridaStudio();
    initGameGuardian();
    initAiChat();
    initUploadHandler();
});

// --- Navigation Tabs ---
function initNavigation() {
    const navButtons = document.querySelectorAll(".nav-btn");
    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTab = btn.getAttribute("data-tab");
            
            navButtons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");

            document.querySelectorAll(".tab-pane").forEach(pane => {
                pane.classList.remove("active");
            });

            const activePane = document.getElementById(targetTab);
            if (activePane) {
                activePane.classList.add("active");
            }
        });
    });
}

// --- Platform Diagnostics ---
async function initPlatformDiagnostics() {
    try {
        const res = await fetch("/api/system/info");
        const data = await res.json();
        const badge = document.getElementById("platformName");
        if (badge) {
            badge.textContent = data.platform || (data.is_termux ? "Android (Termux)" : "Linux OS");
        }
        logConsole(`[System] Detected Runtime: ${data.platform} (${data.arch})`, "info");
        if (data.tools && Object.keys(data.tools).length > 0) {
            logConsole(`[Tools] Native tools detected: ${Object.keys(data.tools).join(", ")}`, "info");
        }
    } catch (e) {
        console.error("Failed to load platform info", e);
    }
}

// --- Real-time WebSocket Logs ---
function initWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/logs`;

    try {
        wsConnection = new WebSocket(wsUrl);

        wsConnection.onopen = () => {
            logConsole("[WS] Connected to live event stream.", "success");
        };

        wsConnection.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === "agent_event") {
                    handleAgentEvent(msg.data);
                } else if (msg.type === "ai_status") {
                    logConsole(`[AI Router] ${msg.message}`, "info");
                }
            } catch (err) {
                logConsole(`[Stream] ${event.data}`, "info");
            }
        };

        wsConnection.onclose = () => {
            setTimeout(initWebSocket, 3000);
        };
    } catch (err) {
        console.warn("WebSocket initialization error:", err);
    }
}

// --- APK List & Selection ---
async function loadApkList() {
    try {
        const res = await fetch("/api/apk/list");
        const data = await res.json();
        currentApksList = data.apks || [];
        
        const select = document.getElementById("currentApkSelect");
        if (!select) return;

        select.innerHTML = "";
        if (currentApksList.length === 0) {
            select.innerHTML = '<option value="">No APKs loaded</option>';
            return;
        }

        currentApksList.forEach((apk, idx) => {
            const opt = document.createElement("option");
            opt.value = apk.path;
            opt.textContent = `${apk.name} (${apk.category.toUpperCase()}) - ${(apk.size / (1024*1024)).toFixed(2)} MB`;
            select.appendChild(opt);
        });

        currentApkPath = select.value;
        select.onchange = () => {
            currentApkPath = select.value;
            logConsole(`[Active APK] Changed to: ${currentApkPath}`, "info");
        };

        document.getElementById("btnRefreshApks").onclick = loadApkList;
    } catch (e) {
        console.error("Failed to load APKs", e);
    }
}

// --- Console Logger ---
function logConsole(message, type = "info") {
    const box = document.getElementById("consoleOutput");
    if (!box) return;
    const p = document.createElement("p");
    p.className = `log-line ${type}`;
    p.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    box.appendChild(p);
    box.scrollTop = box.scrollHeight;
}

document.getElementById("btnClearConsole")?.addEventListener("click", () => {
    const box = document.getElementById("consoleOutput");
    if (box) box.innerHTML = "";
});

// --- Tab 1: Autonomous AI Modding Agent ---
function initAutonomousAgent() {
    const btnRun = document.getElementById("btnRunAgentTask");
    const promptInput = document.getElementById("agentPromptInput");
    const providerSelect = document.getElementById("agentProviderSelect");

    btnRun?.addEventListener("click", async () => {
        const prompt = promptInput.value.trim();
        if (!prompt) {
            alert("Please enter a modding instruction for the AI agent.");
            return;
        }
        if (!currentApkPath) {
            alert("Please select or upload a target APK first.");
            return;
        }

        // Show progress UI
        document.getElementById("agentLiveProgress").classList.remove("hidden");
        document.getElementById("agentResultBanner").classList.add("hidden");
        document.getElementById("agentProgressBar").style.width = "5%";
        document.getElementById("agentCurrentStep").textContent = "Starting AI Agent...";
        document.getElementById("agentLiveLog").innerHTML = "";

        logConsole(`[Agent] Initiating Autonomous Mod Task on: ${currentApkPath}`, "info");

        try {
            const res = await fetch("/api/ai/autonomous_mod", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    apk_path: currentApkPath,
                    prompt: prompt,
                    provider_preference: providerSelect.value || null
                })
            });

            const result = await res.json();
            if (result.success) {
                document.getElementById("agentProgressBar").style.width = "100%";
                document.getElementById("agentCurrentStep").textContent = "Completed!";
                document.getElementById("agentPercent").textContent = "100%";

                // Show download banner
                const banner = document.getElementById("agentResultBanner");
                banner.classList.remove("hidden");
                const btnDownload = document.getElementById("btnDownloadModdedApk");
                btnDownload.href = `/api/apk/download/${result.output_filename}`;
                btnDownload.textContent = `📥 Download ${result.output_filename} (${(result.size_bytes / (1024*1024)).toFixed(2)} MB)`;

                logConsole(`[✓] Autonomous Modding complete! Generated: ${result.output_filename}`, "success");
                loadApkList();
            } else {
                alert(`Error: ${result.detail || "Modding failed"}`);
            }
        } catch (err) {
            logConsole(`[Error] Autonomous mod error: ${err}`, "error");
        }
    });
}

function handleAgentEvent(event) {
    const bar = document.getElementById("agentProgressBar");
    const stepLabel = document.getElementById("agentCurrentStep");
    const percentLabel = document.getElementById("agentPercent");
    const logBox = document.getElementById("agentLiveLog");

    if (bar && event.progress) {
        bar.style.width = `${event.progress}%`;
        percentLabel.textContent = `${event.progress}%`;
    }
    if (stepLabel && event.step) {
        stepLabel.textContent = `Step: ${event.step.toUpperCase()}`;
    }
    if (logBox && event.detail) {
        const item = document.createElement("div");
        item.textContent = `> ${event.detail}`;
        logBox.appendChild(item);
        logBox.scrollTop = logBox.scrollHeight;
    }
    logConsole(`[Agent] ${event.step}: ${event.detail}`, "info");
}

function setPresetPrompt(text) {
    const input = document.getElementById("agentPromptInput");
    if (input) {
        input.value = text;
        input.scrollIntoView({ behavior: "smooth" });
    }
}

// --- Tab 2: Lucky Patcher ---
function initLuckyPatcher() {
    const btn = document.getElementById("btnRunLuckyPatch");
    btn?.addEventListener("click", async () => {
        if (!currentApkPath) return alert("Select an APK first.");
        btn.disabled = true;
        btn.textContent = "Applying Lucky Patches...";

        const payload = {
            apk_path: currentApkPath,
            remove_ads: document.getElementById("lpRemoveAds").checked,
            bypass_billing: document.getElementById("lpBypassBilling").checked,
            bypass_license: document.getElementById("lpBypassLicense").checked,
            bypass_root: document.getElementById("lpBypassRoot").checked,
            sign: document.getElementById("lpAutoSign").checked
        };

        try {
            const res = await fetch("/api/apk/lucky_patch", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            const outBox = document.getElementById("luckyPatchResult");
            outBox.classList.remove("hidden");
            outBox.innerHTML = `<strong>✓ Lucky Patch Complete!</strong><br>Output APK: ${data.output_apk}<br>Size: ${(data.size_bytes / (1024*1024)).toFixed(2)} MB`;
            logConsole(`[Lucky Patcher] Applied modifications to ${currentApkPath}`, "success");
            loadApkList();
        } catch (err) {
            logConsole(`[Error] Lucky Patcher failed: ${err}`, "error");
        } finally {
            btn.disabled = false;
            btn.textContent = "🍀 Apply Selected Lucky Patches";
        }
    });
}

// --- Tab 3: Apktool M ---
function initApktoolM() {
    const btn = document.getElementById("btnRunApktoolM");
    btn?.addEventListener("click", async () => {
        if (!currentApkPath) return alert("Select an APK first.");
        
        const payload = {
            apk_path: currentApkPath,
            package_name: document.getElementById("mPackageName").value.trim() || null,
            debuggable: document.getElementById("mDebuggable").value ? (document.getElementById("mDebuggable").value === "true") : null,
            remove_ad_perms: document.getElementById("mStripAdPerms").checked,
            remove_dangerous_perms: document.getElementById("mStripDangerousPerms").checked
        };

        try {
            const res = await fetch("/api/apk/quick_edit", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            const outBox = document.getElementById("apktoolMResult");
            outBox.classList.remove("hidden");
            outBox.innerHTML = `<strong>⚡ Apktool M Quick Edit Complete!</strong><br>Output: ${data.output_apk}<br>Removed Permissions: ${data.permissions_removed?.join(", ") || "None"}`;
            logConsole(`[Apktool M] Quick edit saved to: ${data.output_apk}`, "success");
            loadApkList();
        } catch (err) {
            logConsole(`[Error] Apktool M failed: ${err}`, "error");
        }
    });
}

// --- Tab 4: JADX & Smali Studio ---
function initDecompilerStudio() {
    const btnDecompile = document.getElementById("btnDecompileFull");
    btnDecompile?.addEventListener("click", async () => {
        if (!currentApkPath) return alert("Select an APK first.");
        btnDecompile.disabled = true;
        btnDecompile.textContent = "Decompiling (Apktool + JADX)...";

        try {
            const res = await fetch("/api/apk/decompile", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ apk_path: currentApkPath })
            });
            const data = await res.json();
            
            const tree = document.getElementById("codeFileTree");
            tree.innerHTML = "";

            if (data.jadx?.classes) {
                Object.keys(data.jadx.classes).forEach(clsName => {
                    const item = document.createElement("div");
                    item.className = "tree-item";
                    item.style.padding = "4px 8px";
                    item.style.cursor = "pointer";
                    item.textContent = `☕ ${clsName}`;
                    item.onclick = () => {
                        document.getElementById("currentOpenedFile").textContent = clsName;
                        document.getElementById("codeDisplayArea").textContent = `// Loading ${clsName}...`;
                        fetchClassSource(clsName, data.jadx.classes[clsName].file);
                    };
                    tree.appendChild(item);
                });
            }
            logConsole(`[JADX] Decompiled ${data.jadx?.java_files_count || 0} classes to Java AST`, "success");
        } catch (err) {
            logConsole(`[Error] Decompile failed: ${err}`, "error");
        } finally {
            btnDecompile.disabled = false;
            btnDecompile.textContent = "Decompile Active APK";
        }
    });

    document.getElementById("btnSearchXref")?.addEventListener("click", async () => {
        const query = document.getElementById("codeSearchInput").value.trim();
        if (!query || !currentApkPath) return;

        try {
            const res = await fetch("/api/apk/batch_regex", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ apk_path: currentApkPath, pattern: query })
            });
            const data = await res.json();
            const tree = document.getElementById("codeFileTree");
            tree.innerHTML = `<strong>Found ${data.count} matches for '${query}':</strong><br>`;
            data.matches?.forEach(m => {
                const div = document.createElement("div");
                div.textContent = `[${m.dex}] ${m.match}`;
                div.style.padding = "2px 0";
                tree.appendChild(div);
            });
        } catch (e) {}
    });
}

async function fetchClassSource(clsName, filePath) {
    // For preview, display synthesized class java
    document.getElementById("codeDisplayArea").textContent = `// Class: ${clsName}
package com.target.app;

public class MainActivity extends android.app.Activity {
    
    // Method: isPremium() - Code Offset: 0x120
    public boolean isPremium() {
        // [OmniAPK Hooked/Patched] VIP Premium Verification
        return true;
    }

    // Method: isRooted() - Code Offset: 0x138
    public boolean isRooted() {
        // [OmniAPK Hooked/Patched] Root/Emulator Check Bypassed
        return false;
    }

    // Method: showInterstitialAd() - Code Offset: 0x150
    public void showInterstitialAd() {
        return;
    }
}`;
}

// --- Tab 5: MT Manager ---
function initMtManager() {
    const btnMerge = document.getElementById("btnMergeSplits");
    btnMerge?.addEventListener("click", async () => {
        const input = document.getElementById("splitApkInput").value.trim();
        if (!input) return alert("Enter split APK paths");
        const paths = input.split(",").map(p => p.trim());

        try {
            const res = await fetch("/api/apk/split_merge", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ apk_paths: paths })
            });
            const data = await res.json();
            const box = document.getElementById("splitMergeResult");
            box.classList.remove("hidden");
            box.innerHTML = `<strong>✓ Split APKs Merged into Standalone APK!</strong><br>Output: ${data.merged_apk}<br>Total DEX files merged: ${data.total_dex_count}`;
            logConsole(`[MT Manager] Merged ${paths.length} split APKs into standalone`, "success");
            loadApkList();
        } catch (err) {
            logConsole(`[Error] Split merge failed: ${err}`, "error");
        }
    });

    const btnBatch = document.getElementById("btnExecuteBatchRegex");
    btnBatch?.addEventListener("click", async () => {
        if (!currentApkPath) return alert("Select an APK first.");
        const pattern = document.getElementById("regexSearchPattern").value.trim();
        const replacement = document.getElementById("regexReplaceStr").value.trim();

        try {
            const res = await fetch("/api/apk/batch_regex", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    apk_path: currentApkPath,
                    pattern: pattern,
                    replacement: replacement || null
                })
            });
            const data = await res.json();
            const box = document.getElementById("batchRegexResult");
            box.classList.remove("hidden");
            box.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
            loadApkList();
        } catch (err) {
            logConsole(`[Error] Batch regex failed: ${err}`, "error");
        }
    });

    const btnDiff = document.getElementById("btnRunApkDiff");
    btnDiff?.addEventListener("click", async () => {
        const apkA = document.getElementById("diffApkA").value.trim();
        const apkB = document.getElementById("diffApkB").value.trim();
        if (!apkA || !apkB) return alert("Enter paths for APK A and APK B");

        try {
            const res = await fetch("/api/apk/diff", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ apk_a: apkA, apk_b: apkB })
            });
            const data = await res.json();
            const box = document.getElementById("apkDiffResult");
            box.classList.remove("hidden");
            box.innerHTML = `<strong>📊 APK Differences Found (${data.total_diff_count} changes):</strong><br>
Added files: ${data.added_files.length}<br>
Removed files: ${data.removed_files.length}<br>
Modified files: ${data.modified_files.join(", ") || "None"}`;
        } catch (e) {}
    });
}

// --- Tab 6: APK Editor Resource Manager ---
function loadResourcesCategory(category) {
    const box = document.getElementById("resourceListTable");
    if (!box) return;
    box.innerHTML = `<p class="placeholder-text">Loading category '${category}'...</p>`;

    // Render sample resource items
    setTimeout(() => {
        box.innerHTML = `
        <table style="width:100%; font-size:0.8rem; border-collapse:collapse;">
            <thead>
                <tr style="border-bottom:1px solid var(--border-color); text-align:left;">
                    <th style="padding:6px;">Resource Path</th>
                    <th>Type</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
                    <td style="padding:8px;">res/values/strings.xml</td>
                    <td>XML / String Pool</td>
                    <td><button class="btn-secondary-sm" onclick="alert('In-place resource replacement modal ready')">Replace</button></td>
                </tr>
                <tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
                    <td style="padding:8px;">assets/game_config.json</td>
                    <td>JSON Config</td>
                    <td><button class="btn-secondary-sm" onclick="alert('In-place asset replacement ready')">Replace</button></td>
                </tr>
                <tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
                    <td style="padding:8px;">AndroidManifest.xml</td>
                    <td>AXML Binary</td>
                    <td><button class="btn-secondary-sm" onclick="alert('Manifest editor ready')">Edit</button></td>
                </tr>
            </tbody>
        </table>`;
    }, 200);
}

// --- Tab 7: Frida Generator ---
function initFridaStudio() {
    const btn = document.getElementById("btnGenerateFridaScript");
    btn?.addEventListener("click", async () => {
        const pkg = currentApkPath || "com.target.sampleapp";
        const cls = document.getElementById("fridaClass").value.trim() || null;
        const meth = document.getElementById("fridaMethod").value.trim() || null;
        const ret = document.getElementById("fridaReturn").value.trim() || null;

        try {
            const res = await fetch("/api/frida/generate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    package_name: pkg,
                    class_name: cls,
                    method_name: meth,
                    return_value: ret
                })
            });
            const data = await res.json();
            let code = data.ssl_unpinning + "\n\n" + data.root_bypass;
            if (data.custom_hook) {
                code += "\n\n" + data.custom_hook;
            }
            document.getElementById("fridaCodeOutput").textContent = code;
            logConsole("[Frida] Generated Universal SSL + Root + Custom hook script", "success");
        } catch (err) {
            logConsole(`[Error] Frida generation failed: ${err}`, "error");
        }
    });
}

// --- Tab 8: Game Guardian ---
function initGameGuardian() {
    const btnFirst = document.getElementById("btnGgFirstSearch");
    const btnRefine = document.getElementById("btnGgRefine");
    const btnWrite = document.getElementById("btnGgWriteAll");
    const btnLua = document.getElementById("btnGgGenerateLua");

    btnFirst?.addEventListener("click", async () => {
        const val = parseFloat(document.getElementById("ggSearchVal").value);
        const type = document.getElementById("ggSearchType").value;

        try {
            const res = await fetch("/api/game_guardian/search", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ value: val, value_type: type, is_refine: false })
            });
            const data = await res.json();
            const box = document.getElementById("ggSearchResults");
            box.classList.remove("hidden");
            box.innerHTML = `<strong>🎮 Memory Scan Found ${data.matches_count} Addresses:</strong><br>${data.addresses.join(", ")}`;
            logConsole(`[Game Guardian] Found ${data.matches_count} RAM addresses matching ${val}`, "info");
        } catch (e) {}
    });

    btnRefine?.addEventListener("click", async () => {
        const val = parseFloat(document.getElementById("ggSearchVal").value);
        try {
            const res = await fetch("/api/game_guardian/search", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ value: val, is_refine: true })
            });
            const data = await res.json();
            const box = document.getElementById("ggSearchResults");
            box.innerHTML = `<strong>🎯 Refined to ${data.matches_count} Addresses:</strong><br>${data.addresses.join(", ")}`;
        } catch (e) {}
    });

    btnWrite?.addEventListener("click", async () => {
        const val = parseFloat(document.getElementById("ggNewVal").value);
        try {
            const res = await fetch("/api/game_guardian/edit", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ new_value: val })
            });
            const data = await res.json();
            logConsole(`[Game Guardian] Modified ${data.edited_count} RAM values to ${data.new_value}`, "success");
            alert(`Modified ${data.edited_count} memory addresses to ${data.new_value}!`);
        } catch (e) {}
    });

    btnLua?.addEventListener("click", async () => {
        const val = parseFloat(document.getElementById("ggSearchVal").value);
        const newVal = parseFloat(document.getElementById("ggNewVal").value);
        try {
            const res = await fetch("/api/game_guardian/generate_lua", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    game_name: "TargetGame",
                    searches: [{ name: "Coins", target_val: val, new_val: newVal, type: "DWORD" }],
                    speedhack: 2.0
                })
            });
            const data = await res.json();
            document.getElementById("ggLuaScriptBox").classList.remove("hidden");
            document.getElementById("ggLuaCode").textContent = data.lua_script;
            logConsole("[Game Guardian] Exported Lua mod script", "success");
        } catch (e) {}
    });
}

// --- Tab 9: AI Reverse Engineering Chat ---
function initAiChat() {
    const btnSend = document.getElementById("btnSendAiChat");
    const input = document.getElementById("aiChatInput");

    btnSend?.addEventListener("click", async () => {
        const text = input.value.trim();
        if (!text) return;
        input.value = "";

        appendChatMessage("user", text);

        try {
            const res = await fetch("/api/ai/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    messages: [
                        { role: "system", content: "You are the expert OmniAPK reverse engineering AI assistant." },
                        { role: "user", content: text }
                    ]
                })
            });
            const data = await res.json();
            appendChatMessage("ai", data.content || "Done.");
        } catch (err) {
            appendChatMessage("ai", `Error communicating with AI: ${err}`);
        }
    });
}

function appendChatMessage(role, text) {
    const container = document.getElementById("aiChatMessages");
    if (!container) return;
    const bubble = document.createElement("div");
    bubble.className = `chat-bubble ${role}`;
    bubble.innerHTML = `<div class="bubble-header">${role === "ai" ? "🤖 OmniAI Assistant" : "👤 You"}</div><p>${text.replace(/\n/g, '<br>')}</p>`;
    container.appendChild(bubble);
    container.scrollTop = container.scrollHeight;
}

// --- Upload Handler & Dropzone ---
function initUploadHandler() {
    const fileInput = document.getElementById("apkFileInput");
    fileInput?.addEventListener("change", async () => {
        if (!fileInput.files.length) return;
        const file = fileInput.files[0];
        const formData = new FormData();
        formData.append("file", file);

        logConsole(`[Upload] Uploading ${file.name}...`, "info");
        try {
            const res = await fetch("/api/apk/upload", {
                method: "POST",
                body: formData
            });
            const data = await res.json();
            if (data.success) {
                logConsole(`[Upload] Uploaded ${file.name} successfully!`, "success");
                closeUploadModal();
                loadApkList();
            }
        } catch (err) {
            logConsole(`[Error] Upload failed: ${err}`, "error");
        }
    });

    document.getElementById("btnUploadModal")?.addEventListener("click", () => {
        document.getElementById("uploadModal").classList.remove("hidden");
    });
}

function closeUploadModal() {
    document.getElementById("uploadModal").classList.add("hidden");
}

// --- AI Settings Modal ---
document.getElementById("btnOpenAiSettings")?.addEventListener("click", async () => {
    document.getElementById("aiSettingsModal").classList.remove("hidden");
    try {
        const res = await fetch("/api/ai/config");
        const data = await res.json();
        // pre-fill custom URL if present
        if (data.custom_endpoints?.custom?.base_url) {
            document.getElementById("customBaseUrl").value = data.custom_endpoints.custom.base_url;
        }
    } catch (e) {}
});

function closeAiModal() {
    document.getElementById("aiSettingsModal").classList.add("hidden");
}

async function saveAiSettings() {
    const groqKey = document.getElementById("keyGroq").value.trim();
    const openaiKey = document.getElementById("keyOpenAI").value.trim();
    const anthropicKey = document.getElementById("keyAnthropic").value.trim();
    const geminiKey = document.getElementById("keyGemini").value.trim();
    const deepseekKey = document.getElementById("keyDeepSeek").value.trim();
    const customUrl = document.getElementById("customBaseUrl").value.trim();

    const keys = {
        groq: groqKey ? groqKey.split(",").map(k => k.trim()) : [],
        openai: openaiKey ? openaiKey.split(",").map(k => k.trim()) : [],
        anthropic: anthropicKey ? anthropicKey.split(",").map(k => k.trim()) : [],
        gemini: geminiKey ? geminiKey.split(",").map(k => k.trim()) : [],
        deepseek: deepseekKey ? deepseekKey.split(",").map(k => k.trim()) : [],
        custom: []
    };

    const payload = {
        keys: keys,
        custom_endpoints: {
            custom: { base_url: customUrl || "http://localhost:11434/v1", model: "llama3" }
        }
    };

    try {
        await fetch("/api/ai/config", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        logConsole("[AI Settings] Multi-Cloud API keys and endpoints updated successfully", "success");
        closeAiModal();
    } catch (e) {
        alert("Failed to save AI settings");
    }
}
