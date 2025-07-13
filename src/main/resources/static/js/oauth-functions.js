// Функция для обмена кода авторизации на токены
async function exchangeCodeForTokens() {
    const clientId = document.getElementById('clientId').value;
    const clientSecret = document.getElementById('clientSecret').value;
    const authCode = document.getElementById('authCode').value;
    const redirectUri = document.getElementById('redirectUri').value;
    const requestedTtl = document.getElementById('requestedTtl').value;

    const tokenResponse = document.getElementById('tokenResponse');
    tokenResponse.value = 'Выполняется запрос...';

    try {
        const bodyParams = new URLSearchParams({
            'grant_type': 'authorization_code',
            'code': authCode,
            'redirect_uri': redirectUri,
            'client_id': clientId
        });

        if (requestedTtl && requestedTtl > 0) {
            bodyParams.append('requested_token_ttl', requestedTtl);
        }

        const response = await fetch('/oauth2/token', {
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
                tokenResponse.value = JSON.stringify(jsonResponse, null, 2);
                tokenResponse.className = 'form-control border-success';
            } catch (e) {
                tokenResponse.value = responseText;
                tokenResponse.className = 'form-control border-success';
            }
        } else {
            tokenResponse.value = `Ошибка ${response.status}: ${responseText}`;
            tokenResponse.className = 'form-control border-danger';
        }

    } catch (error) {
        tokenResponse.value = `Ошибка сети: ${error.message}`;
        tokenResponse.className = 'form-control border-danger';
    }
}

// Функция для тестирования Client Credentials flow
async function testClientCredentialsFlow() {
    const clientId = document.getElementById('ccClientId').value;
    const clientSecret = document.getElementById('ccClientSecret').value;
    const scope = document.getElementById('ccScope').value;
    const requestedTtl = document.getElementById('ccRequestedTtl').value;

    const ccResponse = document.getElementById('ccResponse');
    ccResponse.value = 'Выполняется запрос...';

    try {
        const bodyParams = new URLSearchParams({
            'grant_type': 'client_credentials',
            'scope': scope
        });

        if (requestedTtl && requestedTtl > 0) {
            bodyParams.append('requested_token_ttl', requestedTtl);
        }

        const response = await fetch('/oauth2/token', {
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
                ccResponse.value = JSON.stringify(jsonResponse, null, 2);
                ccResponse.className = 'form-control border-success';
            } catch (e) {
                ccResponse.value = responseText;
                ccResponse.className = 'form-control border-success';
            }
        } else {
            ccResponse.value = `Ошибка ${response.status}: ${responseText}`;
            ccResponse.className = 'form-control border-danger';
        }

    } catch (error) {
        ccResponse.value = `Ошибка сети: ${error.message}`;
        ccResponse.className = 'form-control border-danger';
    }
}

async function copyJWTDecoded() {

    const successMessage = 'JWT payload скопирован в буфер обмена';
    const payload = document.getElementById('jwtPayload').textContent;

    try {
        // Сначала пробуем Clipboard API
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(payload);
            showToast(successMessage, 'success');
            return true;
        } else {
            // Fallback для модальных окон
            return await copyToClipboard(payload, successMessage);
        }
    } catch (error) {
        console.error('Ошибка копирования в модальном окне:', error);

        // Пробуем fallback
        return await copyToClipboard(payload, successMessage);
    }
}

function testClientCredentials() {
    const modal = new bootstrap.Modal(document.getElementById('clientCredentialsModal'));
    modal.show();
}

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const icon = input.nextElementSibling.querySelector('i');

    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

// Функция для форматирования payload с человекочитаемыми датами
function formatJWTPayload(payload) {
    const formatted = { ...payload };

    // Конвертируем Unix timestamps в читаемые даты
    const timeFields = ['iat', 'exp', 'nbf', 'auth_time'];

    timeFields.forEach(field => {
        if (formatted[field] && typeof formatted[field] === 'number') {
            const date = new Date(formatted[field] * 1000);
            formatted[field + '_human'] = date.toLocaleString('ru-RU');
        }
    });

    return formatted;
}

// Функция для валидации JWT токена
function validateJWTToken(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            return { valid: false, error: 'JWT должен содержать 3 части' };
        }

        const header = JSON.parse(base64UrlDecode(parts[0]));
        const payload = JSON.parse(base64UrlDecode(parts[1]));

        // Проверяем обязательные поля
        if (!header.alg) {
            return { valid: false, error: 'Отсутствует алгоритм подписи в header' };
        }

        // Проверяем срок действия
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
            return { valid: false, error: 'Токен истек' };
        }

        // Проверяем время начала действия
        if (payload.nbf && payload.nbf > Math.floor(Date.now() / 1000)) {
            return { valid: false, error: 'Токен еще не активен' };
        }

        return { valid: true, header, payload };

    } catch (e) {
        return { valid: false, error: 'Ошибка парсинга JWT: ' + e.message };
    }
}

// Функция для декодирования Base64URL (вынесена отдельно для переиспользования)
function base64UrlDecode(str) {
    // Заменяем Base64URL символы на Base64
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

    // Добавляем padding, если необходимо
    while (base64.length % 4) {
        base64 += '=';
    }

    try {
        // 1. Декодируем Base64 в бинарную строку
        const binaryString = atob(base64);
        // 2. Преобразуем бинарную строку в массив байтов (Uint8Array)
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        // 3. Используем TextDecoder для корректного декодирования UTF-8
        const decoder = new TextDecoder('utf-8');
        return decoder.decode(bytes);
    } catch (e) {
        console.error('Ошибка декодирования Base64URL:', e);
        // В случае ошибки возвращаем результат старого метода, чтобы не сломать декодирование не-utf8 данных
        try {
            return decodeURIComponent(escape(atob(base64)));
        } catch (e2) {
            throw new Error('Не удалось декодировать строку Base64URL: ' + e2.message);
        }
    }
}

// Функция для проверки поддержки копирования
function checkClipboardSupport() {
    if (navigator.clipboard && window.isSecureContext) {
        console.log('Clipboard API поддерживается');
        return true;
    } else {
        console.log('Clipboard API не поддерживается, используется fallback');
        return false;
    }
}



// ===== УНИВЕРСАЛЬНЫЕ ФУНКЦИИ =====

/**
 * Универсальная функция для декодирования JWT токена
 * @param {string} sourceElementId - ID элемента с JSON ответом, содержащим токен
 * @param {string} tokenField - поле в JSON, содержащее токен (по умолчанию 'access_token')
 * @param {string} modalToClose - ID модального окна, которое нужно закрыть (опционально)
 */
function decodeJWTUniversal(sourceElementId, tokenField = 'access_token', modalToClose = null) {
    const sourceElement = document.getElementById(sourceElementId);
    const tokenResponse = sourceElement ? sourceElement.value : '';

    if (!tokenResponse.trim()) {
        showToast('Нет данных для декодирования', 'warning');
        return;
    }

    try {
        const tokenData = JSON.parse(tokenResponse);
        const accessToken = tokenData[tokenField];

        if (!accessToken) {
            showToast(`${tokenField} не найден в ответе`, 'warning');
            return;
        }

        const validation = validateJWTToken(accessToken);

        if (!validation.valid) {
            showToast('Ошибка валидации JWT: ' + validation.error, 'danger');
            return;
        }

        // Форматируем payload для лучшего отображения
        const formattedPayload = formatJWTPayload(validation.payload);

        document.getElementById('jwtHeader').textContent = JSON.stringify(validation.header, null, 2);
        document.getElementById('jwtPayload').textContent = JSON.stringify(formattedPayload, null, 2);

        // Закрываем исходное модальное окно, если указано
        if (modalToClose) {
            const sourceModal = bootstrap.Modal.getInstance(document.getElementById(modalToClose));
            if (sourceModal) {
                sourceModal.hide();
            }
        }

        // Показываем модальное окно JWT декодера
        const jwtModal = new bootstrap.Modal(document.getElementById('jwtDecodeModal'));
        jwtModal.show();

        // Показываем информацию о валидности токена
        const now = Math.floor(Date.now() / 1000);
        const expiresIn = validation.payload.exp ? validation.payload.exp - now : null;

        if (expiresIn && expiresIn > 0) {
            const hours = Math.floor(expiresIn / 3600);
            const minutes = Math.floor((expiresIn % 3600) / 60);
            const seconds = expiresIn % 60;
            showToast(`Токен действителен еще ${hours}ч ${minutes}м ${seconds}с`, 'info');
        }

    } catch (e) {
        showToast('Ошибка декодирования JWT: ' + e.message, 'danger');
        console.error('JWT decode error:', e);
    }
}

/**
 * Универсальная функция для показа информации о токене
 * @param {string} sourceElementId - ID элемента с JSON ответом, содержащим токен
 * @param {string} tokenField - поле в JSON, содержащее токен (по умолчанию 'access_token')
 * @param {string} title - заголовок для информационного окна
 */
function showTokenInfoUniversal(sourceElementId, tokenField = 'access_token', title = 'Token Info') {
    const sourceElement = document.getElementById(sourceElementId);
    const tokenResponse = sourceElement ? sourceElement.value : '';

    if (!tokenResponse.trim()) {
        showToast('Нет данных для анализа', 'warning');
        return;
    }

    try {
        const tokenData = JSON.parse(tokenResponse);
        const accessToken = tokenData[tokenField];

        if (!accessToken) {
            showToast(`${tokenField} не найден в ответе`, 'warning');
            return;
        }

        const validation = validateJWTToken(accessToken);

        if (!validation.valid) {
            showToast('Ошибка валидации JWT: ' + validation.error, 'danger');
            return;
        }

        const payload = validation.payload;
        const header = validation.header;
        const now = Math.floor(Date.now() / 1000);

        let info = `
        <div class="card">
            <div class="card-header bg-primary text-white">
                <h6 class="mb-0"><i class="fas fa-info-circle me-2"></i>${title}</h6>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <strong>Основная информация:</strong><br>
                        • Тип: ${header.typ || 'JWT'}<br>
                        • Алгоритм: ${header.alg}<br>
                        • Client ID: ${payload.client_id || payload.sub || 'не указан'}<br>
                        • Издатель: ${payload.iss || 'не указан'}<br>
                    </div>
                    <div class="col-md-6">
                        <strong>Временные метки:</strong><br>
                        • Выдан: ${payload.iat ? new Date(payload.iat * 1000).toLocaleString('ru-RU') : 'не указано'}<br>
                        • Истекает: ${payload.exp ? new Date(payload.exp * 1000).toLocaleString('ru-RU') : 'не указано'}<br>
        `;

        if (payload.exp) {
            const expiresIn = payload.exp - now;
            if (expiresIn > 0) {
                const hours = Math.floor(expiresIn / 3600);
                const minutes = Math.floor((expiresIn % 3600) / 60);
                const seconds = expiresIn % 60;
                info += `• Осталось: ${hours}ч ${minutes}м ${seconds}с<br>`;
                info += `• Статус: <span class="text-success">Действителен</span><br>`;
            } else {
                info += `• Статус: <span class="text-danger">Истек</span><br>`;
            }
        }

        info += `
                    </div>
                </div>
        `;

        // Обработка scope
        if (payload.scope) {
            let scopes = [];

            if (typeof payload.scope === 'string') {
                scopes = payload.scope.split(' ').filter(s => s.trim());
            } else if (Array.isArray(payload.scope)) {
                scopes = payload.scope;
            } else {
                scopes = [String(payload.scope)];
            }

            if (scopes.length > 0) {
                const scopeBadges = scopes.map(scope =>
                    `<span class="badge bg-secondary me-1">${scope}</span>`
                ).join('');

                info += `
                    <div class="row mt-2">
                        <div class="col-12">
                            <strong>Области доступа:</strong><br>
                            ${scopeBadges}
                        </div>
                    </div>
                `;
            }
        }

        info += `
            </div>
        </div>
        `;

        // Показываем toast с информацией
        const toastHtml = `
        <div class="toast align-items-center bg-light border-0" role="alert" style="min-width: 500px; max-width: 600px;">
            <div class="d-flex">
                <div class="toast-body">
                    ${info}
                </div>
                <button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
        `;

        let toastContainer = document.querySelector('.toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
            toastContainer.style.zIndex = '9999';
            document.body.appendChild(toastContainer);
        }

        toastContainer.insertAdjacentHTML('beforeend', toastHtml);

        const toast = toastContainer.lastElementChild;
        const bsToast = new bootstrap.Toast(toast, { delay: 15000 });
        bsToast.show();

        toast.addEventListener('hidden.bs.toast', function() {
            toast.remove();
        });

    } catch (e) {
        showToast('Ошибка получения информации о токене: ' + e.message, 'danger');
        console.error('Token info error:', e);
    }
}

/**
 * Универсальная функция для копирования токена
 * @param {string} sourceElementId - ID элемента с JSON ответом, содержащим токен
 * @param {string} tokenField - поле в JSON, содержащее токен
 * @param {string} successMessage - сообщение при успешном копировании
 */
async function copyTokenUniversal(sourceElementId, tokenField, successMessage) {
    const sourceElement = document.getElementById(sourceElementId);
    const tokenResponse = sourceElement ? sourceElement.value : '';

    if (!tokenResponse.trim()) {
        showToast('Нет данных для копирования', 'warning');
        return false;
    }

    try {
        const tokenData = JSON.parse(tokenResponse);
        const token = tokenData[tokenField];

        if (!token) {
            // Специальные сообщения для разных типов токенов
            let message = `${tokenField} не найден в ответе`;
            if (tokenField === 'refresh_token') {
                message = 'Refresh token не найден. Возможно, используется grant_type, который не выдает refresh_token (например, client_credentials)';
            } else if (tokenField === 'id_token') {
                message = 'ID token не найден. Возможно, не запрашивался scope "openid"';
            }
            showToast(message, 'warning');
            return false;
        }

        await copyToClipboard(token, successMessage);
        return true;

    } catch (error) {
        console.error('Ошибка копирования токена:', error);

        if (error instanceof SyntaxError) {
            showToast('Ошибка парсинга ответа: некорректный JSON', 'danger');
        } else {
            showToast('Ошибка копирования: ' + error.message, 'danger');
        }
        return false;
    }
}

/**
 * Универсальная функция для форматирования JSON ответа
 * @param {string} elementId - ID элемента с JSON ответом
 */
function formatJSONResponseUniversal(elementId) {
    const element = document.getElementById(elementId);

    if (!element || !element.value.trim()) {
        showToast('Нет данных для форматирования', 'warning');
        return;
    }

    try {
        const json = JSON.parse(element.value);
        element.value = JSON.stringify(json, null, 2);
        element.className = 'form-control border-success';
        showToast('JSON отформатирован', 'success');
    } catch (e) {
        showToast('Не удалось отформатировать как JSON: ' + e.message, 'warning');
    }
}

/**
 * Универсальная функция для копирования всего содержимого элемента
 * @param {string} elementId - ID элемента для копирования
 * @param {string} successMessage - сообщение при успешном копировании
 */
async function copyElementContentUniversal(elementId, successMessage) {
    const element = document.getElementById(elementId);

    if (!element || !element.value.trim()) {
        showToast('Нет данных для копирования', 'warning');
        return false;
    }

    try {
        await copyToClipboard(element.value, successMessage);
        return true;
    } catch (error) {
        console.error('Ошибка копирования:', error);
        showToast('Ошибка копирования: ' + error.message, 'danger');
        return false;
    }
}

/**
 * Универсальная функция для очистки содержимого элемента
 * @param {string} elementId - ID элемента для очистки
 */
function clearElementContentUniversal(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.value = '';
        element.className = 'form-control';
    }
}

// ===== ОБЕРТКИ ДЛЯ СОВМЕСТИМОСТИ (старые функции теперь вызывают универсальные) =====

// Основное окно (Authorization Code Flow)
function decodeJWT() {
    decodeJWTUniversal('tokenResponse');
}

function showTokenInfo() {
    showTokenInfoUniversal('tokenResponse', 'access_token', 'Authorization Code Token Info');
}

function copySpecificToken(tokenType) {
    const tokenFieldMap = {
        'access': 'access_token',
        'refresh': 'refresh_token',
        'id': 'id_token'
    };

    const tokenField = tokenFieldMap[tokenType];
    if (!tokenField) {
        showToast('Неизвестный тип токена', 'warning');
        return;
    }

    const messageMap = {
        'access': 'Access token скопирован в буфер обмена',
        'refresh': 'Refresh token скопирован в буфер обмена',
        'id': 'ID token скопирован в буфер обмена'
    };

    copyTokenUniversal('tokenResponse', tokenField, messageMap[tokenType]);
}

function formatTokenResponse() {
    formatJSONResponseUniversal('tokenResponse');
}

function copyTokenResponse() {
    copyElementContentUniversal('tokenResponse', 'Ответ токена скопирован в буфер обмена');
}

function clearTokenResponse() {
    clearElementContentUniversal('tokenResponse');
}

// Client Credentials модальное окно
function decodeCCJWT() {
    decodeJWTUniversal('ccResponse', 'access_token', 'clientCredentialsModal');
}

function showCCTokenInfo() {
    showTokenInfoUniversal('ccResponse', 'access_token', 'Client Credentials Token Info');
}

function copyCCAccessToken() {
    return copyTokenUniversal('ccResponse', 'access_token', 'Access token скопирован в буфер обмена');
}

function formatCCResponse() {
    formatJSONResponseUniversal('ccResponse');
}

function copyCCResponse() {
    return copyElementContentUniversal('ccResponse', 'Ответ Client Credentials скопирован в буфер обмена');
}

function clearCCResponse() {
    clearElementContentUniversal('ccResponse');
}


// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', async function() {
    checkClipboardSupport();

    // Добавляем подсказки для кнопок
    const buttons = document.querySelectorAll('button[onclick*="copy"]');
    buttons.forEach(button => {
        button.setAttribute('title', 'Скопировать в буфер обмена');
    });

});
