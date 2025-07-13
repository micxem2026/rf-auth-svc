// Кастомные скрипты для Authorization Server

document.addEventListener('DOMContentLoaded', function() {

    // Автоматическое скрытие алертов через 5 секунд
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Анимация для кнопок
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            if (!button.disabled) {
                button.classList.add('loading');

                // Убираем класс loading через 2 секунды
                setTimeout(function() {
                    button.classList.remove('loading');
                }, 2000);
            }
        });
    });

    // Валидация формы логина
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;

            if (!username) {
                e.preventDefault();
                showAlert('Пожалуйста, введите имя пользователя', 'danger');
                document.getElementById('username').focus();
                return;
            }

            if (!password) {
                e.preventDefault();
                showAlert('Пожалуйста, введите пароль', 'danger');
                document.getElementById('password').focus();
                return;
            }

            if (password.length < 3) {
                e.preventDefault();
                showAlert('Пароль должен содержать минимум 3 символа', 'danger');
                document.getElementById('password').focus();
                return;
            }
        });
    }

    // Функция для показа алертов
    function showAlert(message, type) {
        const alertHtml = `
            <div class="alert alert-${type} alert-dismissible fade show" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;

        const alertContainer = document.querySelector('.alert-container') ||
            document.querySelector('.card-body');

        if (alertContainer) {
            alertContainer.insertAdjacentHTML('afterbegin', alertHtml);
        }
    }

    // Обработка клавиши Enter в форме логина
    const loginInputs = document.querySelectorAll('#loginForm input');
    loginInputs.forEach(function(input) {
        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                const form = input.closest('form');
                if (form) {
                    form.submit();
                }
            }
        });
    });

    // Функция для показа/скрытия пароля
    const togglePasswordButtons = document.querySelectorAll('#togglePassword');
    togglePasswordButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            const passwordField = document.getElementById('password');
            const icon = button.querySelector('i');

            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
                button.setAttribute('title', 'Скрыть пароль');
            } else {
                passwordField.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
                button.setAttribute('title', 'Показать пароль');
            }
        });
    });

    // Инициализация tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Плавная прокрутка для якорных ссылок
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    anchorLinks.forEach(function(link) {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
});

/**
 * Универсальная функция копирования текста в буфер обмена.
 * Автоматически определяет, запущена ли она внутри модального окна Bootstrap,
 * и корректирует свое поведение для обхода "ловушки фокуса".
 * @param {string} text - Текст для копирования.
 * @param {string} [successMessage='Скопировано в буфер обмена'] - Сообщение при успехе.
 */
async function copyToClipboard(text, successMessage = 'Скопировано в буфер обмена') {
    // 1. Сначала пробуем современный Clipboard API. Он работает всегда и везде.
    if (navigator.clipboard && window.isSecureContext) {
        try {
            await navigator.clipboard.writeText(text);
            showToast(successMessage, 'success');
            return;
        } catch (err) {
            console.warn('Clipboard API не сработал, используется fallback:', err);
        }
    }

    // 2. Fallback для старых браузеров или небезопасного контекста.

    // --- УМНАЯ ЛОГИКА ---
    // Ищем активное модальное окно. Если оно есть, будем добавлять textarea в него.
    // Если нет, добавляем в document.body.
    const activeModal = document.querySelector('.modal.show');
    const parentElement = activeModal || document.body;

    const textArea = document.createElement('textarea');
    textArea.value = text;

    // Стили, чтобы сделать элемент невидимым и не влияющим на верстку
    textArea.style.position = 'absolute';
    textArea.style.left = '-9999px';
    textArea.style.top = '0px';
    textArea.setAttribute('readonly', ''); // Важно для iOS

    parentElement.appendChild(textArea);

    try {
        // Выделяем текст в зависимости от устройства
        if (navigator.userAgent.match(/ipad|iphone/i)) {
            const range = document.createRange();
            range.selectNodeContents(textArea);
            const selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
            textArea.setSelectionRange(0, 999999);
        } else {
            textArea.select();
        }

        const successful = document.execCommand('copy');
        if (successful) {
            showToast(successMessage, 'success');
        } else {
            throw new Error('document.execCommand не вернул true');
        }
    } catch (err) {
        console.error('Ошибка при использовании fallback-метода копирования:', err);
        showToast('Ошибка копирования', 'danger');
    } finally {
        parentElement.removeChild(textArea);
    }
}

// Функция для показа toast уведомлений
function showToast(message, type = 'info') {
    const toastId = 'toast-' + Date.now();
    const toastHtml = `
        <div id="${toastId}" class="toast align-items-center text-white bg-${type} border-0" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-${getToastIcon(type)} me-2"></i>
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;

    let toastContainer = document.querySelector('.toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        toastContainer.style.zIndex = '9999';
        document.body.appendChild(toastContainer);
    }

    toastContainer.insertAdjacentHTML('beforeend', toastHtml);

    const toastElement = document.getElementById(toastId);
    const bsToast = new bootstrap.Toast(toastElement, {
        autohide: true,
        delay: 5000
    });

    bsToast.show();

    // Удаляем toast после скрытия
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}

function getToastIcon(type) {
    switch(type) {
        case 'success': return 'check-circle';
        case 'danger': return 'exclamation-triangle';
        case 'warning': return 'exclamation-triangle';
        case 'info': return 'info-circle';
        default: return 'info-circle';
    }
}

// Функция для форматирования времени
function formatDateTime(date) {
    return new Intl.DateTimeFormat('ru-RU', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    }).format(date);
}

// Обновление времени на странице каждую секунду
setInterval(function() {
    const timeElements = document.querySelectorAll('.current-time');
    timeElements.forEach(function(element) {
        element.textContent = formatDateTime(new Date());
    });
}, 1000);
