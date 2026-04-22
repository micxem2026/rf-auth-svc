document.addEventListener('DOMContentLoaded', function() {
    if (typeof clientsData !== 'undefined' && clientsData) {
        displayClients(clientsData);
    } else {
        console.error('Данные о клиентах (clientsData) не были переданы с сервера.');
        const container = document.getElementById('clientsContainer');
        container.innerHTML = '<div class="alert alert-danger">Не удалось загрузить данные о клиентах.</div>';
    }
});

let currentTestClient = null;

function testClient(clientId, scopes) {
    currentTestClient = clientsData.find(client => client.clientId === clientId);

    document.getElementById('testClientId').value = clientId;
    document.getElementById('testScopes').value = scopes;
    document.getElementById('testClientSecret').value = '';
    document.getElementById('testResult').value = '';
    document.getElementById('testAuthCode').value = '';

    setupGrantTypeOptions();
    setupRedirectUriOptions();

    document.getElementById('testGrantType').value = 'client_credentials';
    onTestGrantTypeChange();

    const modal = new bootstrap.Modal(document.getElementById('testClientModal'));
    modal.show();
}

function setupGrantTypeOptions() {
    const grantTypeSelect = document.getElementById('testGrantType');
    const availableGrantTypes = currentTestClient ? currentTestClient.grantTypes : [];

    grantTypeSelect.innerHTML = '';

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

    redirectUriSelect.innerHTML = '';

    if (redirectUris && redirectUris.length > 0) {
        redirectUris.forEach(uri => {
            const option = document.createElement('option');
            option.value = uri;
            option.textContent = uri;
            redirectUriSelect.appendChild(option);
        });
    } else {
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

    window.open(authUrl, 'oauth2-auth', 'width=600,height=700,scrollbars=yes');
    showToast('Окно авторизации открыто. После получения кода вставьте его в поле "Authorization Code"', 'info');
}

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

    if (grantType === 'authorization_code') {
        const authCode = document.getElementById('testAuthCode').value;
        if (!authCode.trim()) {
            showToast('Введите authorization code', 'warning');
            return;
        }
    }

    resultTextarea.value = 'Выполняется запрос...';

    try {
        const bodyParams = new URLSearchParams({ 'grant_type': grantType });

        if (grantType === 'client_credentials') {
            bodyParams.append('scope', scopes);
        } else if (grantType === 'authorization_code') {
            const authCode = document.getElementById('testAuthCode').value;
            const redirectUri = document.getElementById('testRedirectUri').value;
            bodyParams.append('code', authCode);
            bodyParams.append('redirect_uri', redirectUri);
            bodyParams.append('client_id', clientId);
        }

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
                let tokenInfo = 'Тест выполнен успешно! Получены токены:';
                if (jsonResponse.access_token)  tokenInfo += ' access_token';
                if (jsonResponse.refresh_token) tokenInfo += ' refresh_token';
                if (jsonResponse.id_token)      tokenInfo += ' id_token';
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
                            <span class="badge bg-secondary ms-2 fw-normal">
                                ${escapeHtml(client.clientId)}
                            </span>
                        </h5>
                        <div class="mb-2">
                            <strong>Grant Types:</strong>
                            ${(client.grantTypes || []).map(gt =>
                                `<span class="badge bg-info me-1">${escapeHtml(gt)}</span>`
                            ).join('')}
                        </div>
                        <div class="mb-2">
                            <strong>Scopes:</strong>
                            ${(client.scopes || []).map(scope =>
                                `<span class="badge bg-success me-1">${escapeHtml(scope)}</span>`
                            ).join('')}
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
                            ${client.protectedClient ? `
                            <button class="btn btn-outline-secondary btn-sm"
                                    title="Защищённый клиент — изменение и удаление заблокированы"
                                    onclick="showProtectedClientInfo('${escapeHtml(client.clientId)}')"
                                    disabled>
                                <i class="fas fa-lock"></i>
                                Защищён
                            </button>` : `
                            <button class="btn btn-outline-secondary btn-sm"
                                    onclick="editClient('${escapeHtml(client.clientId)}')">
                                <i class="fas fa-edit"></i>
                                Изменить
                            </button>
                            <button class="btn btn-outline-danger btn-sm"
                                    onclick="confirmDelete('${escapeHtml(client.clientId)}', '${escapeHtml(client.clientName)}')">
                                <i class="fas fa-trash"></i>
                                Удалить
                            </button>`}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `).join('');

    container.innerHTML = clientsHtml;
}

function escapeHtml(unsafe) {
    if (unsafe === null || typeof unsafe === 'undefined') return '';
    return unsafe.toString()
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}


function showProtectedClientInfo(clientId) {
    showToast(
        `Клиент "${clientId}" защищён от изменения и удаления. ` +
        'Снять защиту можно в настройках клиента через базу данных.',
        'info'
    );
}

let currentDeleteClientId = null;

function confirmDelete(clientId, clientName) {
    currentDeleteClientId = clientId;
    document.getElementById('deleteClientName').textContent = clientName;
    const modal = new bootstrap.Modal(document.getElementById('deleteConfirmModal'));
    modal.show();
}

function decodeTestJWT() {
    decodeJWTUniversal('testResult', 'access_token', 'testClientModal');
}

function showTestTokenInfo() {
    showTokenInfoUniversal('testResult', 'access_token', 'Test Client Token Info');
}

async function copyTestAccessToken() {
    return copyTokenUniversal('testResult', 'access_token', 'Access token скопирован в буфер обмена');
}

function formatTestResult() {
    formatJSONResponseUniversal('testResult');
}

async function copyTestResult() {
    return copyElementContentUniversal('testResult', 'Результат теста скопирован в буфер обмена');
}

function clearTestResult() {
    clearElementContentUniversal('testResult');
}

async function editClient(clientId) {
    try {
        const csrfToken  = document.querySelector('meta[name="_csrf"]').getAttribute('content');
        const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute('content');

        const headers = {};
        headers[csrfHeader] = csrfToken;

        const response = await fetch(`/auth/admin/api/clients/${clientId}`, {
            method: 'GET',
            headers: headers,
            credentials: 'same-origin'
        });

        if (!response.ok) {
            let errorMessage = 'Ошибка загрузки данных клиента';
            try {
                const error = await response.json();
                errorMessage = error.error || errorMessage;
            } catch(e) {}
            showToast(errorMessage, 'danger');
            return;
        }

        const clientData = await response.json();
        populateEditForm(clientData);
        const modal = new bootstrap.Modal(document.getElementById('editClientModal'));
        modal.show();
    } catch (error) {
        console.error('Error loading client data:', error);
        showToast('Ошибка загрузки данных клиента', 'danger');
    }
}

function populateEditForm(clientData) {
    document.getElementById('editClientOriginalId').value = clientData.clientId;
    document.getElementById('editClientName').value = clientData.clientName || '';
    document.getElementById('editClientId').value = clientData.clientId || '';

    document.querySelectorAll('#editClientModal input[type="checkbox"]').forEach(cb => cb.checked = false);

    document.getElementById('editRequireAuthorizationConsent').checked = clientData.requireAuthorizationConsent || false;
    document.getElementById('editRequireProofKey').checked = clientData.requireProofKey || false;
    document.getElementById('editReuseRefreshTokens').checked = clientData.reuseRefreshTokens || false;

    if (clientData.grantTypes) {
        clientData.grantTypes.forEach(grantType => {
            const checkbox = document.querySelector(`#editClientModal input[value="${grantType}"]`);
            if (checkbox) checkbox.checked = true;
        });
    }

    if (clientData.scopes) {
        clientData.scopes.forEach(scope => {
            const checkbox = document.querySelector(`#editClientModal input[value="${scope}"]`);
            if (checkbox) checkbox.checked = true;
        });
    }

    if (clientData.redirectUris && clientData.redirectUris.length > 0) {
        document.getElementById('editRedirectUris').value = clientData.redirectUris.join('\n');
    } else {
        document.getElementById('editRedirectUris').value = '';
    }

    toggleEditAuthCodeFields();
    toggleEditRefreshTokenFields();
    setupEditFormHandlers();
}

function setupEditFormHandlers() {
    const authCodeCheckbox   = document.getElementById('editGrantAuthCode');
    const refreshTokenCheckbox = document.getElementById('editGrantRefreshToken');
    if (authCodeCheckbox)    authCodeCheckbox.addEventListener('change', toggleEditAuthCodeFields);
    if (refreshTokenCheckbox) refreshTokenCheckbox.addEventListener('change', toggleEditRefreshTokenFields);
}

function toggleEditAuthCodeFields() {
    const authCodeCheckbox  = document.getElementById('editGrantAuthCode');
    const redirectUrisGroup = document.getElementById('editRedirectUrisGroup');
    if (authCodeCheckbox && redirectUrisGroup) {
        redirectUrisGroup.style.display = authCodeCheckbox.checked ? 'block' : 'none';
        const redirectUrisInput = document.getElementById('editRedirectUris');
        if (redirectUrisInput) redirectUrisInput.required = authCodeCheckbox.checked;
    }
}

function toggleEditRefreshTokenFields() {
    const refreshTokenCheckbox   = document.getElementById('editGrantRefreshToken');
    const refreshTokenTtlGroup   = document.getElementById('editRefreshTokenTtlGroup');
    const reuseRefreshTokensGroup = document.getElementById('editReuseRefreshTokensGroup');
    if (refreshTokenCheckbox && refreshTokenTtlGroup && reuseRefreshTokensGroup) {
        const display = refreshTokenCheckbox.checked ? 'block' : 'none';
        refreshTokenTtlGroup.style.display   = display;
        reuseRefreshTokensGroup.style.display = display;
    }
}

async function saveClientChanges() {
    const originalClientId = document.getElementById('editClientOriginalId').value;
    const formData = collectEditFormData();

    if (!validateEditFormData(formData)) return;

    const saveButton = document.querySelector('#editClientModal .btn-primary');
    const originalText = saveButton.innerHTML;
    saveButton.disabled = true;
    saveButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Сохранение...';

    try {
        const csrfToken  = document.querySelector('meta[name="_csrf"]').getAttribute('content');
        const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute('content');

        const headers = { 'Content-Type': 'application/json' };
        headers[csrfHeader] = csrfToken;

        const response = await fetch(`/auth/admin/api/clients/${originalClientId}`, {
            method: 'PUT',
            headers: headers,
            credentials: 'same-origin',
            body: JSON.stringify(formData)
        });

        if (response.ok) {
            showToast('Клиент успешно обновлен', 'success');
            const modal = bootstrap.Modal.getInstance(document.getElementById('editClientModal'));
            if (modal) modal.hide();
            window.location.reload();
        } else {
            const errorText = await response.text();
            let errorMessage = errorText;
            try {
                const errorData = JSON.parse(errorText);
                errorMessage = errorData.error || errorData.message || errorMessage;
            } catch (e) {}
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

function collectEditFormData() {
    const grantTypes = [];
    document.querySelectorAll('#editClientModal input[type="checkbox"][id^="editGrant"]:checked')
        .forEach(cb => grantTypes.push(cb.value));

    const scopes = [];
    document.querySelectorAll('#editClientModal input[type="checkbox"][id^="editScope"]:checked')
        .forEach(cb => scopes.push(cb.value));

    const redirectUris = [];
    const redirectUrisText = document.getElementById('editRedirectUris').value.trim();
    if (redirectUrisText) {
        redirectUrisText.split('\n').forEach(uri => {
            const trimmedUri = uri.trim();
            if (trimmedUri) redirectUris.push(trimmedUri);
        });
    }

    return {
        clientName:                  document.getElementById('editClientName').value.trim(),
        clientId:                    document.getElementById('editClientId').value.trim(),
        grantTypes,
        scopes,
        redirectUris:                redirectUris.length > 0 ? redirectUris : null,
        accessTokenTtlSeconds:       parseInt(document.getElementById('editAccessTokenTtl').value) || 3600,
        refreshTokenTtlSeconds:      parseInt(document.getElementById('editRefreshTokenTtl').value) || 2592000,
        requireAuthorizationConsent: document.getElementById('editRequireAuthorizationConsent').checked,
        requireProofKey:             document.getElementById('editRequireProofKey').checked,
        reuseRefreshTokens:          document.getElementById('editReuseRefreshTokens').checked,
        isUpdate: true
    };
}

function validateEditFormData(formData) {
    if (!formData.clientName) { showToast('Введите название клиента', 'warning'); return false; }
    if (!formData.clientId)   { showToast('Введите Client ID', 'warning'); return false; }
    if (formData.grantTypes.length === 0) { showToast('Выберите хотя бы один Grant Type', 'warning'); return false; }
    if (formData.scopes.length === 0) { showToast('Выберите хотя бы один Scope', 'warning'); return false; }
    if (formData.grantTypes.includes('authorization_code') &&
        (!formData.redirectUris || formData.redirectUris.length === 0)) {
        showToast('Для Authorization Code grant требуется указать Redirect URIs', 'warning');
        return false;
    }
    return true;
}

document.getElementById('confirmDeleteBtn').addEventListener('click', async function() {
    if (!currentDeleteClientId) return;

    try {
        const csrfToken  = document.querySelector('meta[name="_csrf"]').getAttribute('content');
        const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute('content');

        const headers = {};
        headers[csrfHeader] = csrfToken;

        const response = await fetch(`/auth/admin/api/clients/${currentDeleteClientId}`, {
            method: 'DELETE',
            headers: headers,
            credentials: 'same-origin'
        });

        if (response.ok) {
            showToast('Клиент успешно удален', 'success');
            window.location.reload();
        } else {
            let errorMessage = 'Server error';
            try {
                const error = await response.json();
                errorMessage = error.error || errorMessage;
            } catch(e) {}
            showToast('Ошибка при удалении клиента: ' + errorMessage, 'danger');
        }
    } catch (error) {
        console.error('Error deleting client:', error);
        showToast('Ошибка сети при удалении клиента', 'danger');
    }

    const modal = bootstrap.Modal.getInstance(document.getElementById('deleteConfirmModal'));
    if (modal) modal.hide();

    currentDeleteClientId = null;
});
