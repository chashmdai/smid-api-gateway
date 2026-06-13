package cl.smid.apigateway.api.error;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.Map;

/**
 * Sobre de error unificado del ecosistema SMID (Núcleo 2.5).
 *
 * <p><strong>Contrato literal CONGELADO</strong> al formato vigente de
 * {@code smid-auth} 1.0.0 (decisión D2 de la auditoría): campos
 * {@code ruta} (no {@code path}), {@code mensaje} (no {@code message}) y
 * {@code detalles} como <em>mapa opcional</em> {@code campo -> mensaje}.
 * Cualquier vuelta al formato {@code path} + lista exigiría un cambio
 * coordinado de todo el ecosistema, no una edición local de este record.</p>
 *
 * <p>Serialización de referencia (idéntica a la que emite {@code smid-auth}):</p>
 * <pre>{@code
 * {
 *   "status": 401,
 *   "error": "Unauthorized",
 *   "codigo": "AUTZ-003",
 *   "mensaje": "No autenticado. Debe presentar un token de acceso válido.",
 *   "ruta": "/api/personas/8f3b...",
 *   "timestamp": "2026-06-12T19:25:46.737771Z"
 * }
 * }</pre>
 *
 * <p>El orden de los componentes del record fija el orden de los campos JSON.
 * {@code timestamp} es {@link Instant}: el {@code ObjectMapper} de Spring Boot
 * (con {@code JavaTimeModule} y {@code WRITE_DATES_AS_TIMESTAMPS} desactivado)
 * lo serializa como string ISO-8601 en UTC, alineado con {@code smid-auth}.</p>
 *
 * @param status    estado HTTP numérico (redundante con la línea de estado,
 *                  pero parte del contrato para consumo directo del cuerpo)
 * @param error     frase de razón HTTP en inglés (p. ej. {@code "Unauthorized"})
 * @param codigo    código estable del catálogo ({@code AUTZ-xxx} / {@code GTW-xxx});
 *                  el frontend conmuta sobre este campo, nunca sobre {@code mensaje}
 * @param mensaje   descripción humana en español, apta para usuario final
 * @param detalles  mapa {@code campo -> mensaje de validación}; solo presente en
 *                  errores de validación de DTO (el Gateway no los produce: el
 *                  campo existe para completitud del contrato y se omite del
 *                  JSON cuando es {@code null})
 * @param ruta      ruta de la petición que originó el error
 * @param timestamp instante UTC de generación del error
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(
		int status,
		String error,
		String codigo,
		String mensaje,
		Map<String, String> detalles,
		String ruta,
		Instant timestamp) {

	/**
	 * Fábrica del sobre sin {@code detalles} (caso general del Gateway).
	 * El {@code timestamp} se fija al instante de invocación.
	 */
	public static ErrorResponse de(int status, String error, String codigo,
			String mensaje, String ruta) {
		return new ErrorResponse(status, error, codigo, mensaje, null, ruta, Instant.now());
	}

	/**
	 * Fábrica del sobre con {@code detalles} de validación campo a campo.
	 * Reservada para coherencia de contrato; en el Gateway no hay validación
	 * de DTOs de negocio, pero el sobre debe poder transportarla.
	 */
	public static ErrorResponse conDetalles(int status, String error, String codigo,
			String mensaje, Map<String, String> detalles, String ruta) {
		return new ErrorResponse(status, error, codigo, mensaje, detalles, ruta, Instant.now());
	}
}
