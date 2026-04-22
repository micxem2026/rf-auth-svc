'use strict';

// ================================================================
// Состояние
// ================================================================
let allPermissions = [];         // Весь список прав с сервера
let deleteTargetId  = null;      // ID права, ожидающего удаления

// ================================================================
// Инициализация
// ================================================================
document.addEventListener('DOMContentLoaded', () => {
    fetchAndDisplayPermissions();

    document.getElementById('confirmDeletePermissionBtn')
        .addEventListener('click', executeDelete);

    // Загружаем данные вкладки "Назначение ролей" при первом открытии
    const assignTabBtn = document.getElementById('assign-tab-btn');
    if (assignTabBtn) {
        assignTabBtn.addEventListener('shown.bs.tab', () => {
            loadAssignTab();
        });
    }
});

// ================================================================
// Загрузка и отображение прав
// ================================================================
async function fetchAndDisplayPermissions() {
    const tbody = document.getElementById('permissionsTableBody');
    tbody.innerHTML = loadingRow(7);

    try {
        const response = await fetch('/auth/api/permissions', {
            credentials: 'same-origin'
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        allPermissions = await response.json();
        renderPermissionsTable(allPermissions);
    } catch (err) {
        console.error('Error loading permissions:', err);
        tbody.innerHTML = errorRow(7, 'Ошибка загрузки прав доступа');
    }
}

function renderPermissionsTable(permissions) {
    const tbody = document.getElementById('permissionsTableBody');

    if (!permissions.length) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">
            Права не найдены. Нажмите «Добавить право».
        </td></tr>`;
        return;
    }

    tbody.innerHTML = permissions.map(p => `
        <tr data-service="${escapeHtml(p.service)}"
            data-resource="${escapeHtml(p.resource)}"
            data-action="${escapeHtml(p.action)}">
            <td><small class="text-muted">${p.id}</small></td>
            <td>
                <span class="badge bg-light text-primary border border-primary">
                    ${escapeHtml(p.service)}
                </span>
            </td>
            <td><code>${escapeHtml(p.resource)}</code></td>
            <td><code>${escapeHtml(p.action)}</code></td>
            <td><small class="text-muted">${escapeHtml(p.description || '—')}</small></td>
            <td>
                <button class="btn btn-sm btn-outline-secondary"
                        onclick="switchToRolesTab()"
                        title="Перейти к управлению ролями">
                    <i class="fas fa-user-tag me-1"></i>Роли
                </button>
            </td>
            ${IS_ADMIN ? `
            <td>
                <button class="btn btn-sm btn-outline-danger"
                        onclick="confirmDeletePermission(${p.id},
                                 '${escapeHtml(p.service)}:${escapeHtml(p.resource)}:${escapeHtml(p.action)}')">
                    <i class="fas fa-trash"></i>
                </button>
            </td>` : '<td></td>'}
        </tr>
    `).join('');
}

// ================================================================
// Фильтрация таблицы
// ================================================================
function filterByService() {
    filterTable();
}

function filterTable() {
    const service = document.getElementById('serviceFilter').value.toLowerCase();
    const search  = document.getElementById('searchInput').value.toLowerCase();

    const rows = document.querySelectorAll('#permissionsTableBody tr[data-service]');
    rows.forEach(row => {
        const rowService  = row.dataset.service.toLowerCase();
        const rowResource = row.dataset.resource.toLowerCase();
        const rowAction   = row.dataset.action.toLowerCase();

        const matchService = !service || rowService === service;
        const matchSearch  = !search
            || rowResource.includes(search)
            || rowAction.includes(search);

        row.style.display = matchService && matchSearch ? '' : 'none';
    });
}

// ================================================================
// Добавление права
// ================================================================
function openAddPermissionModal() {
    document.getElementById('addPermissionForm').reset();
    new bootstrap.Modal(document.getElementById('addPermissionModal')).show();
}

async function handleAddPermission() {
    const service     = document.getElementById('newService').value.trim();
    const resource    = document.getElementById('newResource').value.trim();
    const action      = document.getElementById('newAction').value.trim();
    const description = document.getElementById('newDescription').value.trim();

    if (!service || !resource || !action) {
        showToast('Заполните обязательные поля', 'warning');
        return;
    }

    const csrfToken  = document.querySelector('meta[name="_csrf"]').content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

    try {
        const response = await fetch('/auth/api/permissions', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                [csrfHeader]: csrfToken
            },
            body: JSON.stringify({ service, resource, action, description })
        });

        if (response.ok) {
            bootstrap.Modal.getInstance(
                document.getElementById('addPermissionModal')).hide();
            showToast(
                `Право ${service}:${resource}:${action} создано`, 'success');
            await fetchAndDisplayPermissions();
        } else {
            const err = await response.json();
            showToast(err.error || 'Ошибка создания права', 'danger');
        }
    } catch (err) {
        showToast('Сетевая ошибка: ' + err.message, 'danger');
    }
}

// ================================================================
// Удаление права
// ================================================================
function confirmDeletePermission(id, fullName) {
    deleteTargetId = id;
    document.getElementById('deletePermissionName').textContent = fullName;
    new bootstrap.Modal(document.getElementById('deletePermissionModal')).show();
}

async function executeDelete() {
    if (!deleteTargetId) return;

    const csrfToken  = document.querySelector('meta[name="_csrf"]').content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

    try {
        const response = await fetch(`/auth/api/permissions/${deleteTargetId}`, {
            method: 'DELETE',
            credentials: 'same-origin',
            headers: { [csrfHeader]: csrfToken }
        });

        bootstrap.Modal.getInstance(
            document.getElementById('deletePermissionModal')).hide();

        if (response.ok) {
            showToast('Право удалено', 'success');
            await fetchAndDisplayPermissions();
        } else {
            const err = await response.json();
            showToast(err.error || 'Ошибка удаления', 'danger');
        }
    } catch (err) {
        showToast('Сетевая ошибка: ' + err.message, 'danger');
    } finally {
        deleteTargetId = null;
    }
}

// ================================================================
// Управление ролями (для PERMISSION_MANAGER)
// ================================================================
function openCreateRoleModal() {
    document.getElementById('createRoleForm').reset();
    new bootstrap.Modal(document.getElementById('createRoleModal')).show();
}

async function handleCreateRole() {
    const nameInput = document.getElementById('newRoleName');
    const name        = nameInput.value.trim().toUpperCase();
    const description = document.getElementById('newRoleDescription').value.trim();

    if (!name) {
        showToast('Введите название роли', 'warning');
        return;
    }
    if (!/^[A-Z0-9_]+$/.test(name)) {
        showToast('Название роли: только заглавные буквы, цифры и подчёркивание', 'warning');
        return;
    }

    const csrfToken  = document.querySelector('meta[name="_csrf"]').content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

    try {
        const response = await fetch('/auth/admin/api/roles', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                [csrfHeader]: csrfToken
            },
            body: JSON.stringify({ name, description })
        });

        if (response.ok) {
            const created = await response.json();
            bootstrap.Modal.getInstance(
                document.getElementById('createRoleModal')).hide();
            showToast(`Роль ${created.name} создана`, 'success');
            // Переходим сразу на страницу настройки прав новой роли
            window.location.href = `/auth/admin/permissions/roles/${created.id}`;
        } else {
            const err = await response.json().catch(() => ({}));
            showToast(err.error || 'Ошибка создания роли', 'danger');
        }
    } catch (err) {
        showToast('Сетевая ошибка: ' + err.message, 'danger');
    }
}

// ================================================================
// Переключение на вкладку "Права по ролям"
// ================================================================
function switchToRolesTab() {
    const tabBtn = document.getElementById('roles-tab-btn');
    if (tabBtn) {
        new bootstrap.Tab(tabBtn).show();
        tabBtn.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// ================================================================
// Назначение ролей пользователям (для PERMISSION_MANAGER)
// ================================================================

let myRoles       = [];   // роли созданные текущим пользователем
let allUsers      = [];   // все пользователи системы
let assignLoaded  = false;

async function loadAssignTab() {
    if (assignLoaded) return;
    assignLoaded = true;

    const csrfToken  = document.querySelector('meta[name="_csrf"]').content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

    try {
        const [rolesResp, usersResp] = await Promise.all([
            fetch('/auth/admin/api/roles',         { credentials: 'same-origin' }),
            fetch('/auth/admin/api/users/summary', { credentials: 'same-origin' })
        ]);
        if (!rolesResp.ok || !usersResp.ok) throw new Error('Ошибка загрузки данных');

        const allRoles = await rolesResp.json();
        allUsers       = await usersResp.json();

        // Мои роли — созданные текущим пользователем
        myRoles = IS_ADMIN
            ? allRoles
            : allRoles.filter(r => r.createdBy === CURRENT_USERNAME);

        renderMyRoles();
        renderAssignUsersTable();
    } catch (err) {
        console.error(err);
        showToast('Ошибка загрузки данных: ' + err.message, 'danger');
    }
}

function renderMyRoles() {
    const container = document.getElementById('myRolesBadges');
    if (!container) return;

    if (!myRoles.length) {
        container.innerHTML = '<span class="text-muted">Нет доступных ролей для назначения</span>';
        return;
    }
    container.innerHTML = myRoles.map(r => `
        <span class="badge bg-primary p-2">${escapeHtml(r.name)}</span>
    `).join('');
}

function renderAssignUsersTable() {
    const tbody = document.getElementById('assignUsersTableBody');
    if (!tbody) return;

    if (!allUsers.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">Пользователи не найдены</td></tr>';
        return;
    }

    tbody.innerHTML = allUsers.map(user => {
            // Какие из моих ролей уже назначены этому пользователю
            const userRoleNames = user.roles || [];
            const roleButtons = myRoles.map(role => {
                const hasRole = userRoleNames.includes(role.name);
                return `
                    <button class="btn btn-sm ${hasRole ? 'btn-success' : 'btn-outline-secondary'} me-1 mb-1"
                            onclick="toggleRoleForUser(${user.id}, ${role.id}, ${hasRole}, this)"
                            title="${hasRole ? 'Снять роль' : 'Назначить роль'} ${escapeHtml(role.name)}">
                        <i class="fas ${hasRole ? 'fa-user-minus' : 'fa-user-plus'} me-1"></i>
                        ${escapeHtml(role.name)}
                    </button>`;
            }).join('');

            const typeColor = user.userType === 'SERVICE' ? 'bg-warning text-dark' : 'bg-info';
            return `
                <tr>
                    <td>
                        ${escapeHtml(user.username)}
                        ${user.protectedUser
                            ? '<i class="fas fa-lock text-warning ms-1" title="Системный"></i>'
                            : ''}
                    </td>
                    <td>${escapeHtml(user.displayName)}</td>
                    <td><span class="badge ${typeColor}">${escapeHtml(user.userType)}</span></td>
                    <td>
                        ${userRoleNames.map(r =>
                            `<span class="badge bg-secondary me-1">${escapeHtml(r)}</span>`
                        ).join('')}
                    </td>
                    <td>${roleButtons || '<span class="text-muted">Нет доступных ролей</span>'}</td>
                </tr>`;
        }).join('');
}

async function toggleRoleForUser(userId, roleId, currentlyAssigned, btn) {
    const csrfToken  = document.querySelector('meta[name="_csrf"]').content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

    btn.disabled = true;
    const method = currentlyAssigned ? 'DELETE' : 'POST';

    try {
        const response = await fetch(`/auth/admin/api/users/${userId}/roles/${roleId}`, {
            method,
            credentials: 'same-origin',
            headers: { [csrfHeader]: csrfToken }
        });

        if (response.ok) {
            const updated = await response.json();
            // Обновляем локальные данные
            const userIdx = allUsers.findIndex(u => u.id === userId);
            if (userIdx !== -1) allUsers[userIdx] = updated;
            renderAssignUsersTable();
            showToast(
                currentlyAssigned ? 'Роль снята' : 'Роль назначена',
                'success'
            );
        } else {
            const err = await response.json().catch(() => ({}));
            showToast(err.error || 'Ошибка операции', 'danger');
            btn.disabled = false;
        }
    } catch (err) {
        showToast('Сетевая ошибка: ' + err.message, 'danger');
        btn.disabled = false;
    }
}

// ================================================================
// Утилиты (дублируются из custom.js намеренно — модуль независим)
// ================================================================
function escapeHtml(str) {
    if (str == null) return '';
    return str.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function loadingRow(cols) {
    return `<tr><td colspan="${cols}" class="text-center py-3">
        <div class="spinner-border spinner-border-sm me-2" role="status"></div>
        Загрузка...
    </td></tr>`;
}

function errorRow(cols, msg) {
    return `<tr><td colspan="${cols}" class="text-center text-danger py-3">
        <i class="fas fa-exclamation-triangle me-2"></i>${escapeHtml(msg)}
    </td></tr>`;
}
