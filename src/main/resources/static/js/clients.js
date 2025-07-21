document.addEventListener('DOMContentLoaded', function() {
    // Проверяем, существуют ли данные, переданные с сервера
    if (typeof clientsData !== 'undefined' && clientsData) {
        // Если данные есть, сразу отображаем их
        displayClients(clientsData);
    } else {
        // Если по какой-то причине данные не пришли, показываем сообщение об ошибке
        console.error('Данные о клиентах (clientsData) не были переданы с сервера.');
        const container = document.getElementById('clientsContainer');
        container.innerHTML = '<div class="alert alert-danger">Не удалось загрузить данные о клиентах.</div>';
    }
});

let currentTestClient = null;

function testClient(clientId, scopes) {
    // Найдем данные клиента в clientsData
    currentTestClient = clientsData.find(client => client.clientId === clientId);

    document.getElementById('testClientId').value = clientId;
    document.getElementById('testScopes').value = scopes;
    document.getElementById('testClientSecret').value = '';
    document.getElementById('testResult').value = '';
    document.getElementById('testAuthCode').value = '';

    // Настраиваем доступные grant types
    setupGrantTypeOptions();

    // Настраиваем redirect URIs если есть
    setupRedirectUriOptions();

    // Сбрасываем на client_credentials по умолчанию
    document.getElementById('testGrantType').value = 'client_credentials';
    onTestGrantTypeChange();

    const modal = new bootstrap.Modal(document.getElementById('testClientModal'));
    modal.show();
}

function setupGrantTypeOptions() {
    const grantTypeSelect = document.getElementById('testGrantType');
    const availableGrantTypes = currentTestClient ? currentTestClient.grantTypes : [];

    // Очищаем опции
    grantTypeSelect.innerHTML = '';

    // Добавляем доступные grant types
    if (availableGrantTypes.includes('client_credentials')) {
        const option = document.createElement('option');
        option.value = 'client_credentials';
        option.textContent = 'Client Credentials';
        grantTypeSelect.appendChild(option);
    }

    if (availableGrantTypes.includes('authorization_code')) {
        const option = document.createElement('option');
        option.value = 'authorization_code';
        option.textContent = 'Authorization Code';
        grantTypeSelect.appendChild(option);
    }

    // Если нет доступных grant types, добавляем client_credentials как fallback
    if (grantTypeSelect.children.length === 0) {
        const option = document.createElement('option');
        option.value = 'client_credentials';
        option.textContent = 'Client Credentials';
        grantTypeSelect.appendChild(option);
    }
}

function setupRedirectUriOptions() {
    const redirectUriSelect = document.getElementById('testRedirectUri');
    const redirectUris = currentTestClient ? currentTestClient.redirectUris : [];

    // Очищаем опции
    redirectUriSelect.innerHTML = '';

    if (redirectUris && redirectUris.length > 0) {
        redirectUris.forEach(uri => {
            const option = document.createElement('option');
            option.value = uri;
            option.textContent = uri;
            redirectUriSelect.appendChild(option);
        });
    } else {
        // Добавляем callback по умолчанию
        const option = document.createElement('option');
        option.value = window.location.origin + '/callback';
        option.textContent = window.location.origin + '/callback';
        redirectUriSelect.appendChild(option);
    }
}

function onTestGrantTypeChange() {
    const grantType = document.getElementById('testGrantType').value;
    const authCodeFields = document.getElementById('authCodeFields');

    if (grantType === 'authorization_code') {
        authCodeFields.style.display = 'block';
    } else {
        authCodeFields.style.display = 'none';
    }
}

function startAuthCodeFlow() {
    const clientId = document.getElementById('testClientId').value;
    const scopes = document.getElementById('testScopes').value;
    const redirectUri = document.getElementById('testRedirectUri').value;

    const authUrl = `/auth/oauth2/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}&scope=${encodeURIComponent(scopes)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=test-${Date.now()}`;

    // Открываем в новом окне
    window.open(authUrl, 'oauth2-auth', 'width=600,height=700,scrollbars=yes');

    showToast('Окно авторизации открыто. После получения кода вставьте его в поле "Authorization Code"', 'info');
}

// Обновленная функция testSelectedClient
async function testSelectedClient() {
    const clientId = document.getElementById('testClientId').value;
    const clientSecret = document.getElementById('testClientSecret').value;
    const grantType = document.getElementById('testGrantType').value;
    const scopes = document.getElementById('testScopes').value;
    const requestedTtl = document.getElementById('testRequestedTtl').value;
    const resultTextarea = document.getElementById('testResult');

    if (!clientSecret.trim()) {
        showToast('Введите client secret', 'warning');
        return;
    }

    // Дополнительная валидация для authorization_code
    if (grantType === 'authorization_code') {
        const authCode = document.getElementById('testAuthCode').value;
        if (!authCode.trim()) {
            showToast('Введите authorization code', 'warning');
            return;
        }
    }

    resultTextarea.value = 'Выполняется запрос...';

    try {
        const bodyParams = new URLSearchParams({
            'grant_type': grantType
        });

        if (grantType === 'client_credentials') {
            bodyParams.append('scope', scopes);
        } else if (grantType === 'authorization_code') {
            const authCode = document.getElementById('testAuthCode').value;
            const redirectUri = document.getElementById('testRedirectUri').value;

            bodyParams.append('code', authCode);
            bodyParams.append('redirect_uri', redirectUri);
            bodyParams.append('client_id', clientId);
        }

        // Добавляем кастомный TTL если указан
        if (requestedTtl && requestedTtl > 0) {
            bodyParams.append('requested_token_ttl', requestedTtl);
        }

        const response = await fetch('/auth/oauth2/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic ' + btoa(clientId + ':' + clientSecret)
            },
            body: bodyParams
        });

        const responseText = await response.text();

        if (response.ok) {
            try {
                const jsonResponse = JSON.parse(responseText);
                resultTextarea.value = JSON.stringify(jsonResponse, null, 2);
                resultTextarea.className = 'form-control border-success';

                // Показываем информацию о полученных токенах
                let tokenInfo = `Тест выполнен успешно! Получены токены:`;
                if (jsonResponse.access_token) tokenInfo += ` access_token`;
                if (jsonResponse.refresh_token) tokenInfo += ` refresh_token`;
                if (jsonResponse.id_token) tokenInfo += ` id_token`;

                showToast(tokenInfo, 'success');
            } catch (e) {
                resultTextarea.value = responseText;
                resultTextarea.className = 'form-control border-success';
            }
        } else {
            resultTextarea.value = `Ошибка ${response.status}: ${responseText}`;
            resultTextarea.className = 'form-control border-danger';
            showToast('Ошибка при выполнении теста', 'danger');
        }

    } catch (error) {
        resultTextarea.value = `Ошибка сети: ${error.message}`;
        resultTextarea.className = 'form-control border-danger';
        showToast('Ошибка сети', 'danger');
    }
}

async function copyTestRefreshToken() {
    return copyTokenUniversal('testResult', 'refresh_token', 'Refresh token скопирован в буфер обмена');
}

function displayClients(clients) {
    const container = document.getElementById('clientsContainer');

    if (!clients || clients.length === 0) {
        container.innerHTML = `
            <div class="text-center text-muted p-4">
                <i class="fas fa-inbox fa-3x mb-3"></i>
                <p>Пока нет зарегистрированных клиентов</p>
                <a href="/auth/admin/clients/register" class="btn btn-primary mt-2">
                    <i class="fas fa-plus me-2"></i>
                    Зарегистрировать первого клиента
                </a>
            </div>
        `;
        return;
    }

    const clientsHtml = clients.map(client => `
        <div class="card mb-3 shadow-sm">
            <div class="card-body">
                <div class="row align-items-center">
                    <div class="col-md-8">
                        <h5 class="card-title mb-1">
                            ${escapeHtml(client.clientName)}
                            <span class="badge bg-secondary ms-2 fw-normal">${escapeHtml(client.clientId)}</span>
                        </h5>
                        <div class="mb-2">
                            <strong>Grant Types:</strong>
                            ${(client.grantTypes || []).map(gt => `<span class="badge bg-info me-1">${escapeHtml(gt)}</span>`).join('')}
                        </div>
                        <div class="mb-2">
                            <strong>Scopes:</strong>
                            ${(client.scopes || []).map(scope => `<span class="badge bg-success me-1">${escapeHtml(scope)}</span>`).join('')}
                        </div>
                        <small class="text-muted">
                            Создан: ${new Date(client.createdAt).toLocaleString('ru-RU')}
                            ${client.createdBy ? ` пользователем <strong>${escapeHtml(client.createdBy)}</strong>` : ''}
                        </small>
                    </div>
                    <div class="col-md-4 text-end mt-3 mt-md-0">
                        <div class="btn-group" role="group">
                            <button class="btn btn-outline-primary btn-sm"
                                    onclick="testClient('${escapeHtml(client.clientId)}', '${(client.scopes || []).join(' ')}')">
                                <i class="fas fa-flask"></i>
                                Тест
                            </button>
                            <button class="btn btn-outline-secondary btn-sm"
                                    onclick="editClient('${escapeHtml(client.clientId)}')">
                                <i class="fas fa-edit"></i>
                                Изменить
                            </button>
                            <button class="btn btn-outline-danger btn-sm"
                                    onclick="confirmDelete('${escapeHtml(client.clientId)}', '${escapeHtml(client.clientName)}')">
                                <i class="fas fa-trash"></i>
                                Удалить
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `).join('');

    container.innerHTML = clientsHtml;
}

// Вспомогательная функция для экранирования HTML, чтобы избежать XSS
function escapeHtml(unsafe) {
    if (unsafe === null || typeof unsafe === 'undefined') {
        return '';
    }
    return unsafe
        .toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Функции testClient, confirmDelete и другие остаются без изменений.
// Просто скопируйте их из старого файла clients.js сюда.
let currentDeleteClientId = null;

function confirmDelete(clientId, clientName) {
    currentDeleteClientId = clientId;
    document.getElementById('deleteClientName').textContent = clientName;

    const modal = new bootstrap.Modal(document.getElementById('deleteConfirmModal'));
    modal.show();
}

// Функция для декодирования JWT из результата теста клиента
function decodeTestJWT() {
    decodeJWTUniversal('testResult', 'access_token', 'testClientModal');
}

// Функция для показа информации о токене из теста клиента
function showTestTokenInfo() {
    showTokenInfoUniversal('testResult', 'access_token', 'Test Client Token Info');
}

// Функция для копирования access token из результата теста клиента
async function copyTestAccessToken() {
    return copyTokenUniversal('testResult', 'access_token', 'Access token скопирован в буфер обмена');
}

// Функция для форматирования результата теста клиента
function formatTestResult() {
    formatJSONResponseUniversal('testResult');
}

// Функция для копирования всего результата теста клиента
async function copyTestResult() {
    return copyElementContentUniversal('testResult', 'Результат теста скопирован в буфер обмена');
}

// Функция для очистки результата теста клиента
function clearTestResult() {
    clearElementContentUniversal('testResult');
}

// Функция для открытия модального окна редактирования
async function editClient(clientId) {
    try {
        // Получаем данные клиента с сервера
        const csrfToken = document.querySelector('meta[name="_csrf"]').getAttribute('content');
        const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute('content');

        const headers = {};
        headers[csrfHeader] = csrfToken;

        const response = await fetch(`/auth/admin/api/clients/${clientId}`, {
            method: 'GET',
            headers: headers
        });

        if (!response.ok) {
            let errorMessage = 'Ошибка загрузки данных клиента';
            try {
                const error = await response.json();
                errorMessage = error.error || errorMessage;
            } catch(e) { /* ignore if response is not json */ }
            showToast(errorMessage, 'danger');
            return;
        }

        const clientData = await response.json();

        // Заполняем форму данными клиента
        populateEditForm(clientData);

        // Показываем модальное окно
        const modal = new bootstrap.Modal(document.getElementById('editClientModal'));
        modal.show();

    } catch (error) {
        console.error('Error loading client data:', error);
        showToast('Ошибка загрузки данных клиента', 'danger');
    }
}

// Функция для заполнения формы редактирования
function populateEditForm(clientData) {
    document.getElementById('editClientOriginalId').value = clientData.clientId;
    document.getElementById('editClientName').value = clientData.clientName || '';
    document.getElementById('editClientId').value = clientData.clientId || '';

    // Очищаем все чекбоксы
    document.querySelectorAll('#editClientModal input[type="checkbox"]').forEach(cb => cb.checked = false);

    document.getElementById('editRequireAuthorizationConsent').checked = clientData.requireAuthorizationConsent || false;
    document.getElementById('editRequireProofKey').checked = clientData.requireProofKey || false;
    document.getElementById('editReuseRefreshTokens').checked = clientData.reuseRefreshTokens || false;

    // Заполняем grant types
    if (clientData.grantTypes) {
        clientData.grantTypes.forEach(grantType => {
            const checkbox = document.querySelector(`#editClientModal input[value="${grantType}"]`);
            if (checkbox) checkbox.checked = true;
        });
    }

    // Заполняем scopes
    if (clientData.scopes) {
        clientData.scopes.forEach(scope => {
            const checkbox = document.querySelector(`#editClientModal input[value="${scope}"]`);
            if (checkbox) checkbox.checked = true;
        });
    }

    // Заполняем redirect URIs
    if (clientData.redirectUris && clientData.redirectUris.length > 0) {
        document.getElementById('editRedirectUris').value = clientData.redirectUris.join('\n');
    } else {
        document.getElementById('editRedirectUris').value = '';
    }

    // Настраиваем видимость полей в зависимости от grant types
    toggleEditAuthCodeFields();
    toggleEditRefreshTokenFields();

    // Настраиваем обработчики изменений
    setupEditFormHandlers();
}

// Функция для настройки обработчиков формы редактирования
function setupEditFormHandlers() {
    const authCodeCheckbox = document.getElementById('editGrantAuthCode');
    const refreshTokenCheckbox = document.getElementById('editGrantRefreshToken');

    if (authCodeCheckbox) {
        authCodeCheckbox.addEventListener('change', toggleEditAuthCodeFields);
    }
    if (refreshTokenCheckbox) {
        refreshTokenCheckbox.addEventListener('change', toggleEditRefreshTokenFields);
    }
}

// Функции для показа/скрытия полей в форме редактирования
function toggleEditAuthCodeFields() {
    const authCodeCheckbox = document.getElementById('editGrantAuthCode');
    const redirectUrisGroup = document.getElementById('editRedirectUrisGroup');

    if (authCodeCheckbox && redirectUrisGroup) {
        redirectUrisGroup.style.display = authCodeCheckbox.checked ? 'block' : 'none';

        const redirectUrisInput = document.getElementById('editRedirectUris');
        if (redirectUrisInput) {
            redirectUrisInput.required = authCodeCheckbox.checked;
        }
    }
}

function toggleEditRefreshTokenFields() {
    const refreshTokenCheckbox = document.getElementById('editGrantRefreshToken');
    const refreshTokenTtlGroup = document.getElementById('editRefreshTokenTtlGroup');
    const reuseRefreshTokensGroup = document.getElementById('editReuseRefreshTokensGroup');

    if (refreshTokenCheckbox && refreshTokenTtlGroup && reuseRefreshTokensGroup) {
        const display = refreshTokenCheckbox.checked ? 'block' : 'none';
        refreshTokenTtlGroup.style.display = display;
        reuseRefreshTokensGroup.style.display = display;
    }
}

// Функция для сохранения изменений
async function saveClientChanges() {
    const originalClientId = document.getElementById('editClientOriginalId').value;
    const formData = collectEditFormData();

    if (!validateEditFormData(formData)) {
        return;
    }

    const saveButton = document.querySelector('#editClientModal .btn-primary');
    const originalText = saveButton.innerHTML;
    saveButton.disabled = true;
    saveButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Сохранение...';

    try {
        const csrfToken = document.querySelector('meta[name="_csrf"]').getAttribute('content');
        const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute('content');

        const headers = {
            'Content-Type': 'application/json'
        };
        headers[csrfHeader] = csrfToken;

        const response = await fetch(`/auth/admin/api/clients/${originalClientId}`, {
            method: 'PUT',
            headers: headers,
            body: JSON.stringify(formData)
        });

        if (response.ok) {
            const result = await response.json();
            showToast('Клиент успешно обновлен', 'success');

            // Закрываем модальное окно
            const modal = bootstrap.Modal.getInstance(document.getElementById('editClientModal'));
            if (modal) {
                modal.hide();
            }

            // Перезагружаем страницу для обновления списка
            window.location.reload();
        } else {
            const errorText = await response.text();
            let errorMessage = errorText;
            try {
                const errorData = JSON.parse(errorText);
                errorMessage = errorData.error || errorData.message || errorMessage;
            } catch (e) {
                console.warn("Error response is not a valid JSON:", errorText);
            }
            showToast('Ошибка обновления: ' + errorMessage, 'danger');
        }
    } catch (error) {
        console.error('Update error:', error);
        showToast('Ошибка сети при обновлении: ' + error.message, 'danger');
    } finally {
        saveButton.disabled = false;
        saveButton.innerHTML = originalText;
    }
}

// Функция для сбора данных из формы редактирования
function collectEditFormData() {
    const grantTypes = [];
    document.querySelectorAll('#editClientModal input[type="checkbox"][id^="editGrant"]:checked').forEach(cb => {
        grantTypes.push(cb.value);
    });

    const scopes = [];
    document.querySelectorAll('#editClientModal input[type="checkbox"][id^="editScope"]:checked').forEach(cb => {
        scopes.push(cb.value);
    });

    const redirectUris = [];
    const redirectUrisText = document.getElementById('editRedirectUris').value.trim();
    if (redirectUrisText) {
        redirectUrisText.split('\n').forEach(uri => {
            const trimmedUri = uri.trim();
            if (trimmedUri) {
                redirectUris.push(trimmedUri);
            }
        });
    }

    return {
        clientName: document.getElementById('editClientName').value.trim(),
        clientId: document.getElementById('editClientId').value.trim(),
        grantTypes: grantTypes,
        scopes: scopes,
        redirectUris: redirectUris.length > 0 ? redirectUris : null,
        accessTokenTtlSeconds: parseInt(document.getElementById('editAccessTokenTtl').value) || 3600,
        refreshTokenTtlSeconds: parseInt(document.getElementById('editRefreshTokenTtl').value) || 2592000,
        requireAuthorizationConsent: document.getElementById('editRequireAuthorizationConsent').checked,
        requireProofKey: document.getElementById('editRequireProofKey').checked,
        reuseRefreshTokens: document.getElementById('editReuseRefreshTokens').checked,
        isUpdate: true
    };
}

// Функция для валидации данных формы редактирования
function validateEditFormData(formData) {
    if (!formData.clientName) {
        showToast('Введите название клиента', 'warning');
        return false;
    }

    if (!formData.clientId) {
        showToast('Введите Client ID', 'warning');
        return false;
    }

    if (formData.grantTypes.length === 0) {
        showToast('Выберите хотя бы один Grant Type', 'warning');
        return false;
    }

    if (formData.scopes.length === 0) {
        showToast('Выберите хотя бы один Scope', 'warning');
        return false;
    }

    if (formData.grantTypes.includes('authorization_code') && (!formData.redirectUris || formData.redirectUris.length === 0)) {
        showToast('Для Authorization Code grant требуется указать Redirect URIs', 'warning');
        return false;
    }

    return true;
}

document.getElementById('confirmDeleteBtn').addEventListener('click', async function() {
    if (!currentDeleteClientId) return;

    try {
        const csrfToken = document.querySelector('meta[name="_csrf"]').getAttribute('content');
        const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute('content');

        const headers = {};
        headers[csrfHeader] = csrfToken;

        const response = await fetch(`/auth/admin/api/clients/${currentDeleteClientId}`, {
            method: 'DELETE',
            headers: headers // Добавляем заголовки в запрос
        });

        // ... остальной код без изменений ...
        if (response.ok) {
            showToast('Клиент успешно удален', 'success');
            window.location.reload();
        } else {
            let errorMessage = 'Server error';
            try {
                const error = await response.json();
                errorMessage = error.error || errorMessage;
            } catch(e) { /* ignore if response is not json */ }
            showToast('Ошибка при удалении клиента: ' + errorMessage, 'danger');
        }
    } catch (error) {
        console.error('Error deleting client:', error);
        showToast('Ошибка сети при удалении клиента', 'danger');
    }

    // Закрываем модальное окно после операции
    const modal = bootstrap.Modal.getInstance(document.getElementById('deleteConfirmModal'));
    if (modal) {
        modal.hide();
    }

    currentDeleteClientId = null;
});
