const loginForm = document.getElementById('login-form');
const userInfo = document.getElementById('user-info');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const securityLevelSelect = document.getElementById('security-level');
const loginBtn = document.getElementById('login-btn');
const logoutBtn = document.getElementById('logout-btn');
const userDisplayName = document.getElementById('user-display-name');
const userSecurityLevel = document.getElementById('user-security-level');

const authWarning = document.getElementById('auth-warning');
const syscallContainer = document.getElementById('syscall-container');
const syscallCategory = document.getElementById('syscall-category');
const syscallSelect = document.getElementById('syscall-select');
const parametersForm = document.getElementById('parameters-form');
const executeBtn = document.getElementById('execute-btn');
const confirmExecution = document.getElementById('confirm-execution');
const resultOutput = document.getElementById('result-output');

const authStatusIndicator = document.getElementById('auth-status-indicator');
const syscallCount = document.getElementById('syscall-count');
const securityIncidents = document.getElementById('security-incidents');
const accessLevelBar = document.getElementById('access-level-bar');
const accessLevelText = document.getElementById('access-level-text');

const securityLogs = document.getElementById('security-logs');
const clearLogsBtn = document.getElementById('clear-logs-btn');
const exportLogsBtn = document.getElementById('export-logs-btn');
const searchLogsInput = document.getElementById('search-logs');
const logFilters = document.querySelectorAll('.log-filter');

const syscallDocsModal = document.getElementById('syscall-docs-modal');
const modalTitle = document.getElementById('modal-title');
const modalBody = document.getElementById('modal-body');
const closeModal = document.querySelector('.close-modal');

const state = {
    authenticated: false,
    user: null,
    securityLevel: null,
    systemCalls: {
        file: [
            { id: 'open', name: 'open()', description: 'Opens a file and returns a file descriptor', securityLevel: 'user' },
            { id: 'read', name: 'read()', description: 'Reads data from a file descriptor', securityLevel: 'user' },
            { id: 'write', name: 'write()', description: 'Writes data to a file descriptor', securityLevel: 'user' },
            { id: 'close', name: 'close()', description: 'Closes a file descriptor', securityLevel: 'user' },
            { id: 'chmod', name: 'chmod()', description: 'Changes file permissions', securityLevel: 'admin' }
        ],
        process: [
            { id: 'fork', name: 'fork()', description: 'Creates a new process by duplicating the calling process', securityLevel: 'admin' },
            { id: 'exec', name: 'exec()', description: 'Replaces the current process image with a new process image', securityLevel: 'admin' },
            { id: 'kill', name: 'kill()', description: 'Sends a signal to a process or a group of processes', securityLevel: 'admin' },
            { id: 'wait', name: 'wait()', description: 'Waits for a child process to stop or terminate', securityLevel: 'user' }
        ],
        memory: [
            { id: 'malloc', name: 'malloc()', description: 'Allocates dynamic memory', securityLevel: 'user' },
            { id: 'free', name: 'free()', description: 'Frees dynamically allocated memory', securityLevel: 'user' },
            { id: 'mmap', name: 'mmap()', description: 'Maps files or devices into memory', securityLevel: 'admin' },
            { id: 'munmap', name: 'munmap()', description: 'Unmaps files or devices from memory', securityLevel: 'admin' }
        ],
        network: [
            { id: 'socket', name: 'socket()', description: 'Creates an endpoint for communication', securityLevel: 'user' },
            { id: 'connect', name: 'connect()', description: 'Initiates a connection on a socket', securityLevel: 'user' },
            { id: 'bind', name: 'bind()', description: 'Assigns a name to a socket', securityLevel: 'admin' },
            { id: 'listen', name: 'listen()', description: 'Listens for connections on a socket', securityLevel: 'admin' }
        ]
    },
    syscallParameters: {
        open: [
            { name: 'path', type: 'text', placeholder: '/path/to/file', required: true },
            { name: 'flags', type: 'select', options: ['O_RDONLY', 'O_WRONLY', 'O_RDWR'], required: true }
        ],
        read: [
            { name: 'fd', type: 'number', placeholder: 'File descriptor', required: true },
            { name: 'count', type: 'number', placeholder: 'Bytes to read', required: true }
        ],
        write: [
            { name: 'fd', type: 'number', placeholder: 'File descriptor', required: true },
            { name: 'buffer', type: 'text', placeholder: 'Data to write', required: true }
        ],
        close: [
            { name: 'fd', type: 'number', placeholder: 'File descriptor', required: true }
        ],
        chmod: [
            { name: 'path', type: 'text', placeholder: '/path/to/file', required: true },
            { name: 'mode', type: 'text', placeholder: '0755', required: true }
        ],
        fork: [],
        exec: [
            { name: 'path', type: 'text', placeholder: '/path/to/executable', required: true },
            { name: 'args', type: 'text', placeholder: 'Command arguments', required: false }
        ],
        kill: [
            { name: 'pid', type: 'number', placeholder: 'Process ID', required: true },
            { name: 'signal', type: 'select', options: ['SIGTERM', 'SIGKILL', 'SIGHUP', 'SIGINT'], required: true }
        ],
        wait: [
            { name: 'pid', type: 'number', placeholder: 'Process ID (0 for any child)', required: false }
        ],
        malloc: [
            { name: 'size', type: 'number', placeholder: 'Bytes to allocate', required: true }
        ],
        free: [
            { name: 'pointer', type: 'text', placeholder: 'Memory address', required: true }
        ],
        mmap: [
            { name: 'addr', type: 'text', placeholder: 'Starting address (0 for any)', required: false },
            { name: 'length', type: 'number', placeholder: 'Length in bytes', required: true },
            { name: 'prot', type: 'select', options: ['PROT_READ', 'PROT_WRITE', 'PROT_EXEC', 'PROT_READ|PROT_WRITE'], required: true }
        ],
        munmap: [
            { name: 'addr', type: 'text', placeholder: 'Starting address', required: true },
            { name: 'length', type: 'number', placeholder: 'Length in bytes', required: true }
        ],
        socket: [
            { name: 'domain', type: 'select', options: ['AF_INET', 'AF_UNIX', 'AF_INET6'], required: true },
            { name: 'type', type: 'select', options: ['SOCK_STREAM', 'SOCK_DGRAM'], required: true }
        ],
        connect: [
            { name: 'sockfd', type: 'number', placeholder: 'Socket file descriptor', required: true },
            { name: 'address', type: 'text', placeholder: 'Server address (e.g. 127.0.0.1)', required: true },
            { name: 'port', type: 'number', placeholder: 'Port number', required: true }
        ],
        bind: [
            { name: 'sockfd', type: 'number', placeholder: 'Socket file descriptor', required: true },
            { name: 'address', type: 'text', placeholder: 'Local address (e.g. 0.0.0.0)', required: true },
            { name: 'port', type: 'number', placeholder: 'Port number', required: true }
        ],
        listen: [
            { name: 'sockfd', type: 'number', placeholder: 'Socket file descriptor', required: true },
            { name: 'backlog', type: 'number', placeholder: 'Maximum queue length', required: true }
        ]
    },
    stats: {
        syscallCount: 0,
        securityIncidents: 0
    },
    logs: [
        {
            timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
            type: 'system',
            message: 'System initialized. Waiting for authentication.'
        }
    ]
};

function init() {
    loginBtn.addEventListener('click', handleLogin);
    logoutBtn.addEventListener('click', handleLogout);
    syscallCategory.addEventListener('change', updateSyscallOptions);
    syscallSelect.addEventListener('change', updateParametersForm);
    executeBtn.addEventListener('click', executeSystemCall);
    clearLogsBtn.addEventListener('click', clearLogs);
    exportLogsBtn.addEventListener('click', exportLogs);
    searchLogsInput.addEventListener('input', filterLogs);
    logFilters.forEach(filter => {
        filter.addEventListener('click', applyLogFilter);
    });
    closeModal.addEventListener('click', () => {
        syscallDocsModal.style.display = 'none';
    });
    updateSyscallOptions();

    window.addEventListener('click', (event) => {
        if (event.target === syscallDocsModal) {
            syscallDocsModal.style.display = 'none';
        }
    });


    renderUI();
}

function handleLogin() {
    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();
    const securityLevel = securityLevelSelect.value;

    if (!username || !password) {
        addLog('error', 'Authentication failed: Missing username or password');
        resultOutput.textContent = 'Authentication Error: Please provide a username and password';
        updateSecurityIncidents(1);
        return;
    }

    if (password.length < 4) {
        addLog('error', 'Authentication failed: Password too short');
        resultOutput.textContent = 'Authentication Error: Password too short (minimum 4 characters)';
        updateSecurityIncidents(1);
        return;
    }

    state.authenticated = true;
    state.user = username;
    state.securityLevel = securityLevel;

    addLog('auth', `User "${username}" authenticated with ${securityLevel} privileges`);

    renderUI();
    resetForm();
}

function handleLogout() {
    addLog('auth', `User "${state.user}" logged out`);

    state.authenticated = false;
    state.user = null;
    state.securityLevel = null;

    renderUI();
}

function updateSyscallOptions() {
    const category = syscallCategory.value;
    const options = state.systemCalls[category];

    syscallSelect.innerHTML = '<option value="">Select a system call...</option>';

    options.forEach(syscall => {
        const option = document.createElement('option');
        option.value = syscall.id;
        option.textContent = syscall.name;

        if (syscall.securityLevel === 'admin') {
            option.textContent += ' (Admin)';
        }

        syscallSelect.appendChild(option);
    });

    updateParametersForm();
}

function updateParametersForm() {
    const syscallId = syscallSelect.value;

    parametersForm.innerHTML = '';

    if (!syscallId) {
        parametersForm.innerHTML = '<div class="placeholder-text">Select a system call to view parameters</div>';
        return;
    }

    const parameters = state.syscallParameters[syscallId] || [];

    if (parameters.length === 0) {
        parametersForm.innerHTML = '<div class="placeholder-text">This system call has no parameters</div>';
        return;
    }

    parameters.forEach(param => {
        const formGroup = document.createElement('div');
        formGroup.className = 'form-group';

        const label = document.createElement('label');
        label.textContent = param.name + (param.required ? ' *' : '');
        label.setAttribute('for', `param-${param.name}`);

        let input;

        if (param.type === 'select') {
            input = document.createElement('select');

            param.options.forEach(option => {
                const optionEl = document.createElement('option');
                optionEl.value = option;
                optionEl.textContent = option;
                input.appendChild(optionEl);
            });
        } else {
            input = document.createElement('input');
            input.type = param.type;
            input.placeholder = param.placeholder || '';
        }

        input.id = `param-${param.name}`;
        input.name = param.name;
        input.required = param.required;

        formGroup.appendChild(label);
        formGroup.appendChild(input);
        parametersForm.appendChild(formGroup);
    });

    const docButton = document.createElement('button');
    docButton.type = 'button';
    docButton.className = 'btn btn-small';
    docButton.style.marginTop = '0.5rem';
    docButton.innerHTML = '<i class="fas fa-question-circle"></i> Documentation';
    docButton.addEventListener('click', () => showDocumentation(syscallId));

    parametersForm.appendChild(docButton);
}

function showDocumentation(syscallId) {
    let syscall = null;
    for (const category in state.systemCalls) {
        const found = state.systemCalls[category].find(sc => sc.id === syscallId);
        if (found) {
            syscall = found;
            break;
        }
    }

    if (!syscall) return;

    modalTitle.textContent = syscall.name + ' Documentation';

    let content = `
    <h3>Description</h3>
    <p>${syscall.description}</p>
    <h3>Security Level</h3>
    <p>Required level: <strong>${syscall.securityLevel === 'admin' ? 'Administrator' : 'User'}</strong></p>
  `;

    const parameters = state.syscallParameters[syscallId] || [];
    if (parameters.length > 0) {
        content += '<h3>Parameters</h3><ul>';
        parameters.forEach(param => {
            content += `<li><strong>${param.name}</strong> - ${param.placeholder} (${param.required ? 'Required' : 'Optional'})</li>`;
        });
        content += '</ul>';
    }

    content += `
    <h3>Example Usage</h3>
    <pre>result = ${syscall.name.replace('()', '')}(${parameters.map(p => p.name).join(', ')});</pre>
    
    <h3>Return Value</h3>
    <p>Returns a success/failure value and sets errno on error.</p>
    
    <h3>Security Considerations</h3>
    <p>This system call requires proper validation of input parameters and appropriate privileges.</p>
`;

    modalBody.innerHTML = content;

    // modal
    syscallDocsModal.style.display = 'flex';
}

function executeSystemCall() {
    if (!state.authenticated) {
        addLog('error', 'Unauthorized system call attempt');
        resultOutput.textContent = 'Error: Authentication required to execute system calls';
        updateSecurityIncidents(1);
        return;
    }

    const syscallId = syscallSelect.value;
    if (!syscallId) {
        resultOutput.textContent = 'Error: Please select a system call to execute';
        return;
    }

    let syscallDetails = null;
    for (const category in state.systemCalls) {
        const found = state.systemCalls[category].find(sc => sc.id === syscallId);
        if (found) {
            syscallDetails = found;
            break;
        }
    }

    if (!syscallDetails) {
        resultOutput.textContent = 'Error: Invalid system call';
        return;
    }

    if (syscallDetails.securityLevel === 'admin' && state.securityLevel !== 'admin') {
        addLog('error', `Security violation: User "${state.user}" attempted to execute admin-only system call "${syscallDetails.name}"`);
        resultOutput.textContent = 'Security Error: This system call requires administrator privileges';
        updateSecurityIncidents(1);
        return;
    }

    if (!confirmExecution.checked) {
        resultOutput.textContent = 'Error: Please confirm that this operation is authorized';
        return;
    }

    const parameters = state.syscallParameters[syscallId] || [];
    const paramValues = {};
    let missingRequired = false;

    parameters.forEach(param => {
        const input = document.getElementById(`param-${param.name}`);
        if (input) {
            const value = input.value.trim();
            if (param.required && !value) {
                missingRequired = true;
            }
            paramValues[param.name] = value;
        }
    });

    if (missingRequired) {
        resultOutput.textContent = 'Error: Please fill in all required parameters (marked with *)';
        return;
    }

    const result = simulateSystemCall(syscallDetails, paramValues);

    updateSyscallCount(1);
    addLog('syscall', `System call "${syscallDetails.name}" executed by "${state.user}" with parameters: ${JSON.stringify(paramValues)}`);
    resultOutput.textContent = result;
    resultOutput.classList.add('appear');
    setTimeout(() => {
        resultOutput.classList.remove('appear');
    }, 500);
}

function simulateSystemCall(syscall, params) {
    const simulatedResponses = {
        open: () => {
            const path = params.path || '';
            if (!path || path === '/') {
                return 'Error: Invalid path specified (errno: EINVAL)';
            }
            return `Success: File "${path}" opened with flags ${params.flags || 'O_RDONLY'}\nFile descriptor: ${Math.floor(Math.random() * 1000) + 10}`;
        },
        read: () => {
            const fd = parseInt(params.fd);
            if (isNaN(fd) || fd < 0) {
                return 'Error: Invalid file descriptor (errno: EBADF)';
            }
            return `Success: Read ${params.count || 0} bytes from file descriptor ${fd}\nData: "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."`;
        },
        write: () => {
            const fd = parseInt(params.fd);
            if (isNaN(fd) || fd < 0) {
                return 'Error: Invalid file descriptor (errno: EBADF)';
            }
            const buffer = params.buffer || '';
            return `Success: Wrote ${buffer.length} bytes to file descriptor ${fd}\nBytes written: ${buffer.length}`;
        },
        close: () => {
            const fd = parseInt(params.fd);
            if (isNaN(fd) || fd < 0) {
                return 'Error: Invalid file descriptor (errno: EBADF)';
            }
            return `Success: File descriptor ${fd} closed`;
        },
        chmod: () => {
            const path = params.path || '';
            if (!path) {
                return 'Error: Invalid path specified (errno: EINVAL)';
            }
            return `Success: Changed permissions of "${path}" to ${params.mode || '0755'}`;
        },
        fork: () => {
            const pid = Math.floor(Math.random() * 10000) + 1000;
            return `Success: Created new process\nChild PID: ${pid}`;
        },
        exec: () => {
            const path = params.path || '';
            if (!path) {
                return 'Error: No executable specified (errno: ENOENT)';
            }
            return `Success: Executed "${path}" with arguments "${params.args || ''}"`;
        },
        kill: () => {
            const pid = parseInt(params.pid);
            if (isNaN(pid) || pid < 0) {
                return 'Error: Invalid process ID (errno: ESRCH)';
            }
            return `Success: Signal ${params.signal || 'SIGTERM'} sent to process ${pid}`;
        },
        wait: () => {
            const pid = parseInt(params.pid) || 0;
            return `Success: Waited for process ${pid || 'any child'}\nProcess status: Exited with code 0`;
        },
        malloc: () => {
            const size = parseInt(params.size);
            if (isNaN(size) || size <= 0) {
                return 'Error: Invalid allocation size (errno: EINVAL)';
            }
            const address = '0x' + Math.floor(Math.random() * 0xFFFFFFFF).toString(16).padStart(8, '0').toUpperCase();
            return `Success: Allocated ${size} bytes of memory\nMemory address: ${address}`;
        },
        free: () => {
            const pointer = params.pointer || '';
            if (!pointer.startsWith('0x')) {
                return 'Error: Invalid memory address (errno: EINVAL)';
            }
            return `Success: Freed memory at address ${pointer}`;
        },
        mmap: () => {
            const length = parseInt(params.length);
            if (isNaN(length) || length <= 0) {
                return 'Error: Invalid mapping length (errno: EINVAL)';
            }
            const address = '0x' + Math.floor(Math.random() * 0xFFFFFFFF).toString(16).padStart(8, '0').toUpperCase();
            return `Success: Mapped ${length} bytes of memory with protection ${params.prot || 'PROT_READ'}\nMemory address: ${address}`;
        },
        munmap: () => {
            const addr = params.addr || '';
            if (!addr.startsWith('0x')) {
                return 'Error: Invalid memory address (errno: EINVAL)';
            }
            return `Success: Unmapped memory at address ${addr} with length ${params.length || 0}`;
        },
        socket: () => {
            const sockfd = Math.floor(Math.random() * 1000) + 3;
            return `Success: Created socket with domain ${params.domain || 'AF_INET'} and type ${params.type || 'SOCK_STREAM'}\nSocket descriptor: ${sockfd}`;
        },
        connect: () => {
            const sockfd = parseInt(params.sockfd);
            if (isNaN(sockfd) || sockfd < 0) {
                return 'Error: Invalid socket descriptor (errno: EBADF)';
            }
            return `Success: Connected socket ${sockfd} to ${params.address || '127.0.0.1'}:${params.port || 80}`;
        },
        bind: () => {
            const sockfd = parseInt(params.sockfd);
            if (isNaN(sockfd) || sockfd < 0) {
                return 'Error: Invalid socket descriptor (errno: EBADF)';
            }
            return `Success: Bound socket ${sockfd} to ${params.address || '0.0.0.0'}:${params.port || 8080}`;
        },
        listen: () => {
            const sockfd = parseInt(params.sockfd);
            if (isNaN(sockfd) || sockfd < 0) {
                return 'Error: Invalid socket descriptor (errno: EBADF)';
            }
            return `Success: Socket ${sockfd} listening with backlog ${params.backlog || 5}`;
        }
    };

    const simulator = simulatedResponses[syscall.id];
    if (simulator) {
        return simulator();
    }

    return `Executed system call: ${syscall.name} with parameters: ${JSON.stringify(params)}`;
}

function updateSyscallCount(increment) {
    state.stats.syscallCount += increment;
    syscallCount.textContent = state.stats.syscallCount;

    syscallCount.classList.add('pulse');
    setTimeout(() => {
        syscallCount.classList.remove('pulse');
    }, 2000);
}

function updateSecurityIncidents(increment) {
    state.stats.securityIncidents += increment;
    securityIncidents.textContent = state.stats.securityIncidents;

    securityIncidents.classList.add('pulse');
    setTimeout(() => {
        securityIncidents.classList.remove('pulse');
    }, 2000);
}

function addLog(type, message) {
    const log = {
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        type,
        message
    };

    state.logs.unshift(log); 

    if (state.logs.length > 100) {
        state.logs.pop();
    }

    renderLogs();
}

function renderLogs(filter = 'all') {
    securityLogs.innerHTML = '';

    const filteredLogs = filter === 'all'
        ? state.logs
        : state.logs.filter(log => log.type === filter);

    filteredLogs.forEach(log => {
        const li = document.createElement('li');
        li.className = 'log-entry';

        const timestamp = document.createElement('span');
        timestamp.className = 'timestamp';
        timestamp.textContent = log.timestamp;

        const type = document.createElement('span');
        type.className = `log-type ${log.type}`;
        type.textContent = log.type.toUpperCase();

        const message = document.createElement('span');
        message.className = 'log-message';
        message.textContent = log.message;

        li.appendChild(timestamp);
        li.appendChild(type);
        li.appendChild(message);

        securityLogs.appendChild(li);
    });
}

function clearLogs() {
    if (confirm('Are you sure you want to clear all logs?')) {
        state.logs = [{
            timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
            type: 'system',
            message: 'Logs cleared by user'
        }];
        renderLogs();
    }
}

function exportLogs() {
    const csvContent = state.logs.map(log => {
        return `"${log.timestamp}","${log.type}","${log.message}"`;
    }).join('\n');

    const header = '"Timestamp","Type","Message"\n';
    const finalContent = header + csvContent;

    const blob = new Blob([finalContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `system_logs_${new Date().toISOString().slice(0, 10)}.csv`);
    link.style.display = 'none';

    document.body.appendChild(link);
    link.click();

    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    addLog('system', 'Logs exported to CSV file');
}

function filterLogs() {
    const searchTerm = searchLogsInput.value.toLowerCase();
    const logEntries = securityLogs.querySelectorAll('.log-entry');

    logEntries.forEach(entry => {
        const message = entry.querySelector('.log-message').textContent.toLowerCase();
        if (message.includes(searchTerm)) {
            entry.style.display = '';
        } else {
            entry.style.display = 'none';
        }
    });
}

function applyLogFilter(event) {
    const filter = event.target.getAttribute('data-filter');

    logFilters.forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-filter') === filter);
    });

    renderLogs(filter);
}

function renderUI() {
    if (state.authenticated) {
        loginForm.style.display = 'none';
        userInfo.style.display = 'block';
        authWarning.style.display = 'none';
        syscallContainer.style.display = 'block';

        userDisplayName.textContent = state.user;
        userSecurityLevel.textContent = state.securityLevel === 'admin' ? 'Administrator' : state.securityLevel;
        userSecurityLevel.className = `badge ${state.securityLevel === 'admin' ? 'admin' : state.securityLevel}`;

        const statusCircle = authStatusIndicator.querySelector('.status-circle');
        const statusText = authStatusIndicator.querySelector('.status-text');

        statusCircle.className = 'status-circle authorized';
        statusText.textContent = 'Authorized';

        let accessLevel = 0;
        switch (state.securityLevel) {
            case 'guest':
                accessLevel = 25;
                accessLevelText.textContent = 'View Only';
                break;
            case 'user':
                accessLevel = 50;
                accessLevelText.textContent = 'Standard Access';
                break;
            case 'admin':
                accessLevel = 100;
                accessLevelText.textContent = 'Full Access';
                break;
        }

        accessLevelBar.style.width = `${accessLevel}%`;
    } else {
        loginForm.style.display = 'block';
        userInfo.style.display = 'none';
        authWarning.style.display = 'block';
        syscallContainer.style.display = 'none';

        const statusCircle = authStatusIndicator.querySelector('.status-circle');
        const statusText = authStatusIndicator.querySelector('.status-text');

        statusCircle.className = 'status-circle unauthorized';
        statusText.textContent = 'Unauthorized';
        accessLevelBar.style.width = '0%';
        accessLevelText.textContent = 'No Access';
    }
}

function resetForm() {
    usernameInput.value = '';
    passwordInput.value = '';
}

document.addEventListener('DOMContentLoaded', init);
