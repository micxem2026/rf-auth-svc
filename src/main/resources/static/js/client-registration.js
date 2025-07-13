let registrationData = null;

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, initializing form handlers...');

    // Показ/скрытие полей в зависимости от выбранных grant types
    const authCodeCheckbox = document.getElementById('grantAuthCode');
    const refreshTokenCheckbox = document.getElementById('grantRefreshToken');

    if (authCodeCheckbox && refreshTokenCheckbox) {
        authCodeCheckbox.addEventListener('change', toggleAuthCodeFields);
        refreshTokenCheckbox.addEventListener('change', toggleRefreshTokenFields);
        console.log('Event listeners added to checkboxes');
    }

    // Обработка формы
    const form = document.getElementById('registerClientForm');
    if (form) {
        form.addEventListener('submit', handleFormSubmit);
        console.log('Form submit handler added');
    }
});

function toggleAuthCodeFields() {
    const authCodeCheckbox = document.getElementById('grantAuthCode');
    const redirectUrisGroup = document.getElementById('redirectUrisGroup');

    if (authCodeCheckbox && redirectUrisGroup) {
        redirectUrisGroup.style.display = authCodeCheckbox.checked ? 'block' : 'none';

        const redirectUrisInput = document.getElementById('redirectUris');
        if (redirectUrisInput) {
            redirectUrisInput.required = authCodeCheckbox.checked;
        }
    }
}

function toggleRefreshTokenFields() {
    const refreshTokenCheckbox = document.getElementById('grantRefreshToken');
    const refreshTokenTtlGroup = document.getElementById('refreshTokenTtlGroup');
    const reuseRefreshTokensGroup = document.getElementById('reuseRefreshTokensGroup');

    if (refreshTokenCheckbox && refreshTokenTtlGroup && reuseRefreshTokensGroup) {
        const display = refreshTokenCheckbox.checked ? 'block' : 'none';
        refreshTokenTtlGroup.style.display = display;
        reuseRefreshTokensGroup.style.display = display;
    }
}

async function handleFormSubmit(e) {
    e.preventDefault();
    console.log('Form submitted');

    const formData = collectFormData();
    console.log('Form data collected:', formData);

    if (!validateFormData(formData)) {
        console.log('Form validation failed');
        return;
    }

    const submitButton = e.target.querySelector('button[type="submit"]');
    const originalText = submitButton.innerHTML;
    submitButton.disabled = true;
    submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Регистрация...';

    try {
        const csrfToken = document.querySelector('meta[name="_csrf"]').getAttribute('content');
        const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute('content');

        console.log('CSRF token:', csrfToken);
        console.log('CSRF header:', csrfHeader);

        const headers = {
            'Content-Type': 'application/json'
        };
        headers[csrfHeader] = csrfToken;

        console.log('Sending POST request to /admin/api/clients');
        console.log('Headers:', headers);

        const response = await fetch('/admin/api/clients', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(formData)
        });

        console.log('Response status:', response.status);

        if (response.ok) {
            const result = await response.json();
            console.log('Registration successful:', result);
            showRegistrationResult(result);
        } else {
            const errorText = await response.text(); // Читаем тело ответа как текст ОДИН РАЗ
            let errorMessage = errorText;
            try {
                // Пытаемся распарсить текст как JSON
                const errorData = JSON.parse(errorText);
                errorMessage = errorData.error || errorData.message || errorMessage;
            } catch (e) {
                // Если не получилось, используем исходный текст ошибки
                console.warn("Error response is not a valid JSON:", errorText);
            }
            console.error('Registration failed:', errorMessage);
            showToast('Ошибка регистрации: ' + errorMessage, 'danger');
        }
    } catch (error) {
        console.error('Registration error:', error);
        showToast('Ошибка сети при регистрации: ' + error.message, 'danger');
    } finally {
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;
    }
}

function collectFormData() {
    const grantTypes = [];
    document.querySelectorAll('input[type="checkbox"][id^="grant"]:checked').forEach(cb => {
        grantTypes.push(cb.value);
    });

    const scopes = [];
    document.querySelectorAll('input[type="checkbox"][id^="scope"]:checked').forEach(cb => {
        scopes.push(cb.value);
    });

    const redirectUris = [];
    const redirectUrisText = document.getElementById('redirectUris').value.trim();
    if (redirectUrisText) {
        redirectUrisText.split('\n').forEach(uri => {
            const trimmedUri = uri.trim();
            if (trimmedUri) {
                redirectUris.push(trimmedUri);
            }
        });
    }

    const clientSecretExpires = document.getElementById('clientSecretExpires').value;

    return {
        clientName: document.getElementById('clientName').value.trim(),
        clientId: document.getElementById('clientId').value.trim(),
        grantTypes: grantTypes,
        scopes: scopes,
        redirectUris: redirectUris.length > 0 ? redirectUris : null,
        clientSecretExpiresInDays: clientSecretExpires ? parseInt(clientSecretExpires) : null,
        accessTokenTtlSeconds: parseInt(document.getElementById('accessTokenTtl').value),
        refreshTokenTtlSeconds: parseInt(document.getElementById('refreshTokenTtl').value),
        requireAuthorizationConsent: document.getElementById('requireAuthorizationConsent').checked,
        requireProofKey: document.getElementById('requireProofKey').checked,
        reuseRefreshTokens: document.getElementById('reuseRefreshTokens').checked
    };
}

function validateFormData(formData) {
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

function showRegistrationResult(result) {
    registrationData = result;

    const resultHtml = `
        <div class="row">
            <div class="col-md-6">
                <h6>Основная информация:</h6>
                <table class="table table-borderless table-sm">
                    <tr>
                        <td><strong>Название:</strong></td>
                        <td>${result.clientName}</td>
                    </tr>
                    <tr>
                        <td><strong>Client ID:</strong></td>
                        <td><code>${result.clientId}</code></td>
                    </tr>
                    <tr>
                        <td><strong>Client Secret:</strong></td>
                        <td><code id="clientSecretDisplay">${result.clientSecret}</code></td>
                    </tr>
                    <tr>
                        <td><strong>Создан:</strong></td>
                        <td>${new Date(result.createdAt).toLocaleString('ru-RU')}</td>
                    </tr>
                </table>
            </div>
            <div class="col-md-6">
                <h6>Настройки:</h6>
                <p><strong>Grant Types:</strong><br>
                ${Array.from(result.grantTypes).map(gt => `<span class="badge bg-info me-1">${gt}</span>`).join('')}</p>
                <p><strong>Scopes:</strong><br>
                ${Array.from(result.scopes).map(scope => `<span class="badge bg-success me-1">${scope}</span>`).join('')}</p>
                ${result.redirectUris && result.redirectUris.length > 0 ? `
                <p><strong>Redirect URIs:</strong><br>
                ${Array.from(result.redirectUris).map(uri => `<small class="text-muted">${uri}</small>`).join('<br>')}</p>
                ` : ''}
            </div>
        </div>
    `;

    document.getElementById('registrationResult').innerHTML = resultHtml;

    const modal = new bootstrap.Modal(document.getElementById('registrationResultModal'));
    modal.show();
}

async function copyClientCredentials() {
    if (!registrationData) return;

    const credentials = `Client ID: ${registrationData.clientId}\nClient Secret: ${registrationData.clientSecret}`;
    await copyToClipboard(credentials, 'Данные клиента скопированы в буфер обмена');
}