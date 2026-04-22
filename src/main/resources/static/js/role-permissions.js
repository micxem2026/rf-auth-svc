'use strict';

// Состояние
let allPermissions    = [];
let assignedIds       = new Set();
let pendingIds        = new Set();
let hasUnsavedChanges = false;

document.addEventListener('DOMContentLoaded', async () => {
    await loadData();
    setupScrollObserver();

    // Если роль защищена — блокируем весь UI редактирования
    if (typeof ROLE_PROTECTED !== 'undefined' && ROLE_PROTECTED) {
        lockProtectedRole();
    }
});

function lockProtectedRole() {
    // Показываем предупреждение
    const alert = document.getElementById('protectedAlert');
    if (alert) alert.classList.remove('d-none');

    // Скрываем кнопки сохранения
    const saveBtn      = document.getElementById('saveBtn');
    const floatingBtn  = document.getElementById('floatingSaveBtn');
    if (saveBtn)     saveBtn.classList.add('d-none');
    if (floatingBtn) floatingBtn.classList.add('d-none');

    // Отключаем все чекбоксы и кнопки быстрого выбора
    document.querySelectorAll(
        '#permissionsContainer input[type="checkbox"], ' +
        '#permissionsContainer button'
    ).forEach(el => { el.disabled = true; });

    // Отключаем кнопки "Выбрать все" / "Снять все" в шапке
    document.querySelectorAll('[onclick^="selectAll"], [onclick^="deselectAll"]')
        .forEach(el => { el.disabled = true; });

    // Блокируем фильтр "Только назначенные" (он всё ещё работает, но меняет нельзя)
    // и переопределяем onPermissionToggle чтобы отменять любые клики
    window.onPermissionToggle = () => {};
}

async function loadData() {
    try {
        const [allResp, roleResp] = await Promise.all([
            fetch('/auth/api/permissions',                  { credentials: 'same-origin' }),
            fetch(`/auth/api/permissions/roles/${ROLE_ID}`, { credentials: 'same-origin' })
        ]);

        if (!allResp.ok)  throw new Error('Ошибка загрузки прав');
        if (!roleResp.ok) throw new Error('Ошибка загрузки прав роли');

        allPermissions = await allResp.json();
        const rolePermissions = await roleResp.json();

        assignedIds = new Set(rolePermissions.map(rp => rp.permissionId));
        pendingIds  = new Set(assignedIds);

        applyFilters();
        updateCounters();
    } catch (err) {
        const c = document.getElementById('permissionsContainer');
        if (c) c.innerHTML = `<div class="alert alert-danger">
            <i class="fas fa-exclamation-triangle me-2"></i>${escapeHtml(err.message)}
        </div>`;
        console.error(err);
    }
}

function applyFilters() {
    const svcFilter    = document.getElementById('svcFilter').value;
    const search       = document.getElementById('rpSearch').value.toLowerCase();
    const assignedOnly = document.getElementById('showAssignedOnly').checked;

    const filtered = allPermissions.filter(p => {
        const matchSvc      = !svcFilter || p.service === svcFilter;
        const matchSearch   = !search
            || p.resource.toLowerCase().includes(search)
            || p.action.toLowerCase().includes(search)
            || (p.description || '').toLowerCase().includes(search);
        const matchAssigned = !assignedOnly || pendingIds.has(p.id);
        return matchSvc && matchSearch && matchAssigned;
    });

    const grouped = {};
    filtered.forEach(p => {
        if (!grouped[p.service])             grouped[p.service] = {};
        if (!grouped[p.service][p.resource]) grouped[p.service][p.resource] = [];
        grouped[p.service][p.resource].push(p);
    });

    const container = document.getElementById('permissionsContainer');
    if (!container) return;

    if (!filtered.length) {
        container.innerHTML = `<div class="alert alert-info">
            <i class="fas fa-info-circle me-2"></i>Нет прав, соответствующих фильтрам.
        </div>`;
        return;
    }

    container.innerHTML = Object.entries(grouped).map(([svc, resources]) => `
        <div class="card mb-3">
            <div class="card-header bg-light d-flex justify-content-between align-items-center">
                <span class="fw-semibold"><i class="fas fa-server me-2"></i>${escapeHtml(svc)}</span>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-outline-success btn-sm"
                            onclick="selectService('${escapeHtml(svc)}')">
                        <i class="fas fa-check me-1"></i>Все
                    </button>
                    <button class="btn btn-outline-secondary btn-sm"
                            onclick="deselectService('${escapeHtml(svc)}')">
                        <i class="fas fa-times me-1"></i>Снять
                    </button>
                </div>
            </div>
            <div class="card-body">
                ${Object.entries(resources).map(([res, perms]) => `
                    <div class="mb-3">
                        <div class="d-flex align-items-center gap-2 mb-2">
                            <code class="text-secondary">${escapeHtml(res)}</code>
                            <small class="text-muted">(${perms.length})</small>
                        </div>
                        <div class="row g-2">
                            ${perms.map(p => `
                                <div class="col-md-6 col-lg-4"
                                     data-service="${escapeHtml(p.service)}"
                                     data-permission-id="${p.id}">
                                    <div class="form-check card p-2 permission-card
                                         ${pendingIds.has(p.id) ? 'border border-success border-2' : 'border'}">
                                        <input class="form-check-input"
                                               type="checkbox"
                                               id="perm_${p.id}"
                                               value="${p.id}"
                                               ${pendingIds.has(p.id) ? 'checked' : ''}
                                               onchange="onPermissionToggle(${p.id}, this.checked)">
                                        <label class="form-check-label w-100" for="perm_${p.id}">
                                            <div class="fw-semibold"><code>${escapeHtml(p.action)}</code></div>
                                            <small class="text-muted">${escapeHtml(p.description || '')}</small>
                                        </label>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `).join('');
}

function onPermissionToggle(permId, checked) {
    if (checked) { pendingIds.add(permId); } else { pendingIds.delete(permId); }

    const card = document.querySelector(`[data-permission-id="${permId}"] .permission-card`);
    if (card) {
        card.classList.toggle('border-success', checked);
        card.classList.toggle('border-2',       checked);
    }

    markChanged();
    updateCounters();
}

function markChanged() {
    const changed = pendingIds.size !== assignedIds.size
        || [...pendingIds].some(id => !assignedIds.has(id))
        || [...assignedIds].some(id => !pendingIds.has(id));

    hasUnsavedChanges = changed;

    const unsavedAlert    = document.getElementById('unsavedAlert');
    const saveBtn         = document.getElementById('saveBtn');
    const floatingSaveBtn = document.getElementById('floatingSaveBtn');

    if (unsavedAlert)    unsavedAlert.classList.toggle('d-none', !changed);
    if (saveBtn)         saveBtn.disabled = !changed;
    if (floatingSaveBtn) floatingSaveBtn.classList.toggle('d-none', !changed);
}

function selectAll() {
    allPermissions.forEach(p => pendingIds.add(p.id));
    applyFilters(); markChanged(); updateCounters();
}

function deselectAll() {
    pendingIds.clear();
    applyFilters(); markChanged(); updateCounters();
}

function selectService(service) {
    allPermissions.filter(p => p.service === service).forEach(p => pendingIds.add(p.id));
    applyFilters(); markChanged(); updateCounters();
}

function deselectService(service) {
    allPermissions.filter(p => p.service === service).forEach(p => pendingIds.delete(p.id));
    applyFilters(); markChanged(); updateCounters();
}

function updateCounters() {
    const assignedVisible = allPermissions.filter(p => pendingIds.has(p.id)).length;
    const ac = document.getElementById('assignedCount');
    const tc = document.getElementById('totalCount');
    if (ac) ac.textContent = `${assignedVisible} назначено`;
    if (tc) tc.textContent = `${allPermissions.length} всего`;
}

async function savePermissions() {
    if (!hasUnsavedChanges) return;

    const saveBtn = document.getElementById('saveBtn');
    const original = saveBtn.innerHTML;
    saveBtn.disabled = true;
    saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Сохранение...';

    const csrfToken  = document.querySelector('meta[name="_csrf"]').content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

    try {
        const response = await fetch(`/auth/api/permissions/roles/${ROLE_ID}`, {
            method: 'PUT',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', [csrfHeader]: csrfToken },
            body: JSON.stringify([...pendingIds])
        });

        if (response.ok) {
            assignedIds       = new Set(pendingIds);
            hasUnsavedChanges = false;

            const unsavedAlert    = document.getElementById('unsavedAlert');
            const floatingSaveBtn = document.getElementById('floatingSaveBtn');
            if (unsavedAlert)    unsavedAlert.classList.add('d-none');
            if (floatingSaveBtn) floatingSaveBtn.classList.add('d-none');

            showToast(`Права роли ${ROLE_NAME} сохранены`, 'success');

            // Обновляем стили карточек без перестройки DOM
            document.querySelectorAll('.permission-card').forEach(card => {
                const wrapper = card.closest('[data-permission-id]');
                if (!wrapper) return;
                const permId = parseInt(wrapper.dataset.permissionId, 10);
                const isAssigned = assignedIds.has(permId);
                card.classList.toggle('border-success', isAssigned);
                card.classList.toggle('border-2',       isAssigned);
            });

            updateCounters();
        } else {
            const err = await response.json().catch(() => ({}));
            showToast(err.error || 'Ошибка сохранения', 'danger');
        }
    } catch (err) {
        showToast('Сетевая ошибка: ' + err.message, 'danger');
    } finally {
        saveBtn.innerHTML = original;
        saveBtn.disabled  = !hasUnsavedChanges;
    }
}

function setupScrollObserver() {
    const saveBtnTop = document.getElementById('saveBtn');
    if (!saveBtnTop) return;

    const observer = new IntersectionObserver(entries => {
        const isVisible   = entries[0].isIntersecting;
        const floatingBtn = document.getElementById('floatingSaveBtn');
        if (!floatingBtn) return;
        if (!isVisible && hasUnsavedChanges) {
            floatingBtn.classList.remove('d-none');
        } else {
            floatingBtn.classList.add('d-none');
        }
    });
    observer.observe(saveBtnTop);
}

window.addEventListener('beforeunload', e => {
    if (hasUnsavedChanges) { e.preventDefault(); e.returnValue = ''; }
});

function escapeHtml(str) {
    if (str == null) return '';
    return str.toString()
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}
