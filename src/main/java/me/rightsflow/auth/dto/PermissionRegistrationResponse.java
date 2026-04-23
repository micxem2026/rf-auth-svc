package me.rightsflow.auth.dto;

import lombok.Builder;
import lombok.Data;

/**
 * Ответ на batch upsert прав.
 */
@Data
@Builder
public class PermissionRegistrationResponse {

    /** Имя сервиса, для которого выполнена регистрация. */
    private String service;

    /** Количество переданных прав. */
    private int total;

    /** Количество созданных (новых) прав. */
    private int created;

    /** Обновлено описание у существующих прав. */
    private int updated;

    /** Количество пропущенных (уже существовавших) прав. */
    private int skipped;
}