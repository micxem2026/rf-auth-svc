document.addEventListener('DOMContentLoaded', () => {
    initializeTabs();

    const addRoleForm = document.getElementById('addRoleForm');
    if (addRoleForm) {
        addRoleForm.addEventListener('submit', handleAddRole);
    }
});

function initializeTabs() {
    const tabs = document.querySelectorAll('#adminTabs .nav-link');

    tabs.forEach(tab => {
        tab.addEventListener('shown.bs.tab', event => {
            const targetPanelId = event.target.getAttribute('data-bs-target');
            history.pushState(null, null, targetPanelId);
            loadDataForTab(event.target);
        });
    });

    const hash = window.location.hash;
    let tabToActivate = document.querySelector(`#adminTabs .nav-link[data-bs-target="${hash}"]`);
    if (!tabToActivate) {
        tabToActivate = document.querySelector('#adminTabs .nav-link');
    }

    if (tabToActivate) {
        new bootstrap.Tab(tabToActivate).show();
        loadDataForTab(tabToActivate);
    }
}

function loadDataForTab(tabElement) {
    const targetPanelId = tabElement.getAttribute('data-bs-target');
    if (targetPanelId === '#users-panel') {
        fetchAndDisplayUsers();
    } else if (targetPanelId === '#roles-panel') {
        fetchAndDisplayRoles();
    }
}

const getCsrfHeaders = () => {
    const token = document.querySelector('meta[name="_csrf"]').getAttribute('content');
    const header = document.querySelector('meta[name="_csrf_header"]').getAttribute('content');
    const headers = new Headers();
    headers.append('Content-Type', 'application/json');
    headers.append(header, token);
    return headers;
};

// --- USER MANAGEMENT ---

async function fetchAndDisplayUsers() {
    const tableBody = document.getElementById('usersTableBody');
    tableBody.innerHTML = `<tr><td colspan="8" class="text-center">
        <div class="spinner-border spinner-border-sm" role="status">
            <span class="visually-hidden">Загрузка...</span>
        </div></td></tr>`;

    try {
        const response = await fetch('/auth/admin/api/users', { credentials: 'same-origin' });
        if (!response.ok) throw new Error('Failed to fetch users');
        const users = await response.json();

        if (users.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-muted">
                Пользователи не найдены.</td></tr>`;
            return;
        }

        tableBody.innerHTML = users.map(user => `
            <tr>
                <td>${user.id}</td>
                <td>
                    ${escapeHtml(user.username)}
                    ${user.protectedUser
                        ? '<i class="fas fa-lock text-warning ms-1" title="Системный пользователь"></i>'
                        : ''}
                </td>
                <td>${escapeHtml(user.displayName)}</td>
                <td>
                    <span class="badge ${user.enabled ? 'bg-success' : 'bg-danger'}">
                        ${user.enabled ? 'Активен' : 'Отключен'}
                    </span>
                </td>
                <td><span class="badge bg-info">${escapeHtml(user.userType)}</span></td>
                <td>${(user.roles || []).map(role =>
                    `<span class="badge bg-secondary me-1">${escapeHtml(role)}</span>`
                ).join('')}</td>
                <td>${user.lastLogon
                    ? new Date(user.lastLogon).toLocaleString('ru-RU') : 'N/A'}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary"
                            onclick="openEditUserModal(${user.id})">
                        <i class="fas fa-edit"></i>
                    </button>
                    ${!user.protectedUser && user.userType !== 'SERVICE' ? `
                    <button class="btn btn-sm btn-outline-danger"
                            onclick="confirmDeleteUser(${user.id}, '${escapeHtml(user.username)}')">
                        <i class="fas fa-trash"></i>
                    </button>` : ''}
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error fetching users:', error);
        tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-danger">
            Ошибка загрузки пользователей.</td></tr>`;
        showToast('Ошибка загрузки пользователей', 'danger');
    }
}

function openAddUserModal() {
    document.getElementById('userForm').reset();
    document.getElementById('userId').value = '';
    document.getElementById('username').disabled = false;
    document.getElementById('userModalTitle').textContent = 'Добавить нового пользователя';
    document.getElementById('passwordHelp').textContent =
        'Пароль обязателен для нового пользователя.';

    // Снимаем блокировку полей (могла остаться от предыдущего защищённого пользователя)
    document.getElementById('enabled').disabled        = false;
    document.getElementById('accountNonLocked').disabled = false;

    const modal = new bootstrap.Modal(document.getElementById('userModal'));
    modal.show();
}

async function openEditUserModal(id) {
    try {
        const response = await fetch(`/auth/admin/api/users/${id}`,
            { credentials: 'same-origin' });
        if (!response.ok) throw new Error('Failed to fetch user data');
        const user = await response.json();

        document.getElementById('userForm').reset();
        document.getElementById('userId').value           = user.id;
        document.getElementById('username').value         = user.username;
        document.getElementById('username').disabled      = true;
        document.getElementById('displayName').value      = user.displayName;
        document.getElementById('email').value            = user.email;
        document.getElementById('enabled').checked        = user.enabled;
        document.getElementById('accountNonLocked').checked = user.accountNonLocked;
        document.getElementById('accountNonExpired').checked = user.accountNonExpired;
        document.getElementById('expirationDate').value   =
            user.expirationDate ? user.expirationDate.substring(0, 16) : '';
        document.getElementById('password').value         = '';
        document.getElementById('passwordHelp').textContent =
            'Оставьте пустым, чтобы не менять пароль.';

        document.querySelectorAll('#rolesCheckboxes input[type="checkbox"]').forEach(cb => {
            cb.checked = user.roles.includes(cb.value);
        });

        // Для защищённых пользователей блокируем enabled и accountNonLocked
        const isProtected = user.protectedUser === true;
        document.getElementById('enabled').disabled         = isProtected;
        document.getElementById('accountNonLocked').disabled = isProtected;
        if (isProtected) {
            document.getElementById('userModalTitle').textContent =
                `Редактировать: ${user.username} (системный)`;
        } else {
            document.getElementById('userModalTitle').textContent =
                `Редактировать пользователя: ${user.username}`;
        }

        const modal = new bootstrap.Modal(document.getElementById('userModal'));
        modal.show();
    } catch (error) {
        console.error('Error fetching user data:', error);
        showToast('Ошибка загрузки данных пользователя', 'danger');
    }
}

async function handleSaveUser() {
    const id = document.getElementById('userId').value;
    const selectedRoles = Array.from(
        document.querySelectorAll('#rolesCheckboxes input:checked')
    ).map(cb => cb.value);

    const userData = {
        username:         document.getElementById('username').value,
        displayName:      document.getElementById('displayName').value,
        email:            document.getElementById('email').value,
        password:         document.getElementById('password').value,
        enabled:          document.getElementById('enabled').checked,
        accountNonLocked: document.getElementById('accountNonLocked').checked,
        accountNonExpired: document.getElementById('accountNonExpired').checked,
        expirationDate:   document.getElementById('expirationDate').value
                            ? document.getElementById('expirationDate').value + ':00'
                            : null,
        roles: selectedRoles
    };

    if (!userData.password) delete userData.password;

    const url    = id ? `/auth/admin/api/users/${id}` : '/auth/admin/api/users';
    const method = id ? 'PUT' : 'POST';

    try {
        const response = await fetch(url, {
            method,
            headers: getCsrfHeaders(),
            credentials: 'same-origin',
            body: JSON.stringify(userData)
        });

        if (response.ok) {
            showToast(`Пользователь успешно ${id ? 'обновлен' : 'создан'}`, 'success');
            const modalEl = document.getElementById('userModal');
            const modalInstance = bootstrap.Modal.getInstance(modalEl);
            modalEl.addEventListener('hidden.bs.modal', () => {
                fetchAndDisplayUsers();
            }, { once: true });
            modalInstance.hide();
        } else {
            const error = await response.json();
            showToast(error.error || 'Ошибка сохранения', 'danger');
        }
    } catch (error) {
        console.error('Error saving user:', error);
        showToast('Сетевая ошибка при сохранении', 'danger');
    }
}

let userToDeleteId = null;
function confirmDeleteUser(id, username) {
    userToDeleteId = id;
    document.getElementById('deleteUsername').textContent = username;
    const modal = new bootstrap.Modal(
        document.getElementById('deleteUserConfirmModal'));
    modal.show();

    document.getElementById('confirmDeleteUserBtn').onclick = async () => {
        try {
            const response = await fetch(`/auth/admin/api/users/${userToDeleteId}`, {
                method: 'DELETE',
                headers: getCsrfHeaders(),
                credentials: 'same-origin'
            });
            if (response.ok) {
                showToast('Пользователь удален', 'success');
                const delModalEl = document.getElementById('deleteUserConfirmModal');
                delModalEl.addEventListener('hidden.bs.modal', () => {
                    fetchAndDisplayUsers();
                }, { once: true });
                bootstrap.Modal.getInstance(delModalEl).hide();
            } else {
                const error = await response.json();
                showToast(error.error || 'Ошибка удаления', 'danger');
                bootstrap.Modal.getInstance(
                    document.getElementById('deleteUserConfirmModal')).hide();
            }
        } catch (error) {
            console.error('Error deleting user:', error);
            showToast('Сетевая ошибка при удалении', 'danger');
            bootstrap.Modal.getInstance(
                document.getElementById('deleteUserConfirmModal')).hide();
        }
    };
}

// --- ROLE MANAGEMENT ---

async function fetchAndDisplayRoles() {
    const tableBody = document.getElementById('rolesTableBody');
    tableBody.innerHTML = `<tr><td colspan="5" class="text-center">
        <div class="spinner-border spinner-border-sm" role="status">
            <span class="visually-hidden">Загрузка...</span>
        </div></td></tr>`;

    try {
        const response = await fetch('/auth/admin/api/roles',
            { credentials: 'same-origin' });
        if (!response.ok) throw new Error('Failed to fetch roles');
        const roles = await response.json();

        if (roles.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">
                Роли не найдены.</td></tr>`;
            return;
        }

        tableBody.innerHTML = roles.map(role => `
            <tr>
                <td>${role.id}</td>
                <td>${escapeHtml(role.name)}</td>
                <td>${escapeHtml(role.description || '')}</td>
                <td>
                    ${role.createdBy === 'system'
                        ? '<span class="badge bg-secondary"><i class="fas fa-lock me-1"></i>Системная</span>'
                        : `<small class="text-muted">${escapeHtml(role.createdBy || '')}</small>`}
                </td>
                <td>
                    ${role.createdBy !== 'system' ? `
                    <button class="btn btn-sm btn-outline-danger"
                            onclick="handleDeleteRole(${role.id})">
                        <i class="fas fa-trash"></i>
                    </button>` : ''}
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error fetching roles:', error);
        tableBody.innerHTML = `<tr><td colspan="4" class="text-center text-danger">
            Ошибка загрузки ролей.</td></tr>`;
        showToast('Ошибка загрузки ролей', 'danger');
    }
}

async function handleAddRole(event) {
    event.preventDefault();
    const roleData = {
        name:        document.getElementById('roleName').value.toUpperCase(),
        description: document.getElementById('roleDescription').value
    };

    try {
        const response = await fetch('/auth/admin/api/roles', {
            method: 'POST',
            headers: getCsrfHeaders(),
            credentials: 'same-origin',
            body: JSON.stringify(roleData)
        });

        if (response.ok) {
            showToast('Роль успешно создана', 'success');
            document.getElementById('addRoleForm').reset();
            window.location.href = window.location.pathname + '#roles-panel';
            fetchAndDisplayRoles();
        } else {
            const error = await response.json();
            showToast(error.error || 'Ошибка создания роли', 'danger');
        }
    } catch (error) {
        console.error('Error adding role:', error);
        showToast('Сетевая ошибка при добавлении роли', 'danger');
    }
}

async function handleDeleteRole(id) {
    if (!confirm('Вы уверены, что хотите удалить эту роль?')) return;
    try {
        const response = await fetch(`/auth/admin/api/roles/${id}`, {
            method: 'DELETE',
            headers: getCsrfHeaders(),
            credentials: 'same-origin'
        });
        if (response.ok) {
            showToast('Роль удалена', 'success');
            window.location.href = window.location.pathname + '#roles-panel';
            fetchAndDisplayRoles();
        } else {
            const error = await response.json();
            showToast(error.error || 'Ошибка удаления роли', 'danger');
        }
    } catch (error) {
        console.error('Error deleting role:', error);
        showToast('Сетевая ошибка при удалении роли', 'danger');
    }
}

function escapeHtml(unsafe) {
    if (unsafe === null || typeof unsafe === 'undefined') return '';
    return unsafe.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
