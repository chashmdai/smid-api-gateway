package cl.smid.apigateway.dominio.error;

import java.util.Optional;

/**
 * Catálogo de códigos de error estables del Gateway (sobre unificado 2.5).
 *
 * <p>Clase de DOMINIO puro: cero dependencias de Spring, Jackson o Netty.
 * El estado HTTP se modela como {@code int} precisamente para no arrastrar
 * tipos de framework hacia el centro del hexágono.</p>
 *
 * <p>El frontend y los servicios consumidores conmutan sobre {@code codigo},
 * jamás sobre {@code mensaje} (el mensaje puede evolucionar; el código no).
 * Resolución de la decisión D1 de la auditoría: prefijo {@code AUTZ-} para
 * autenticación/autorización (consistencia con el ecosistema {@code smid-auth})
 * y prefijo {@code GTW-} para fallas de infraestructura propias del Gateway.</p>
 *
 * <table border="1">
 *   <caption>Catálogo canónico</caption>
 *   <tr><th>Código</th><th>HTTP</th><th>Caso</th></tr>
 *   <tr><td>AUTZ-003</td><td>401</td><td>No autenticado: token ausente, inválido,
 *       vencido, con {@code kid} desconocido o con {@code iss}/{@code aud} ajenos</td></tr>
 *   <tr><td>AUTZ-004</td><td>403</td><td>Acceso denegado por rol/alcance</td></tr>
 *   <tr><td>GTW-001</td><td>503</td><td>Servicio de destino caído (conexión rechazada / DNS)</td></tr>
 *   <tr><td>GTW-002</td><td>504</td><td>Servicio de destino no respondió a tiempo</td></tr>
 *   <tr><td>GTW-404</td><td>404</td><td>Ruta no mapeada en el Gateway</td></tr>
 *   <tr><td>GTW-500</td><td>500</td><td>Error interno del Gateway (el detalle queda
 *       en el log; nunca se filtra al cliente)</td></tr>
 * </table>
 */
public enum CodigoError {

	/** 401 — Sin token, token inválido/vencido, kid desconocido, iss/aud ajenos. */
	AUTZ_003("AUTZ-003", 401,
			"No autenticado. Debe presentar un token de acceso válido."),

	/** 403 — Autenticado pero sin permisos suficientes (rol/alcance). */
	AUTZ_004("AUTZ-004", 403,
			"Acceso denegado. No posee permisos para realizar esta operación."),

	/** 503 — El microservicio de destino está apagado, reiniciándose o irresoluble. */
	GTW_001("GTW-001", 503,
			"El servicio de destino no está disponible temporalmente. Por favor, reintente."),

	/** 504 — El microservicio de destino no respondió dentro del plazo configurado. */
	GTW_002("GTW-002", 504,
			"El servicio de destino no respondió dentro del tiempo máximo permitido."),

	/** 404 — Ningún predicado de ruta del Gateway coincide con la petición. */
	GTW_404("GTW-404", 404,
			"La ruta solicitada no está registrada en el Gateway."),

	/** 500 — Falla no clasificada dentro del propio Gateway. */
	GTW_500("GTW-500", 500,
			"Error interno del API Gateway.");

	/** Prefijo para códigos sintetizados de estados HTTP fuera del catálogo. */
	private static final String PREFIJO_GENERICO = "GTW-";

	private final String codigo;
	private final int estadoHttp;
	private final String mensajePorDefecto;

	CodigoError(String codigo, int estadoHttp, String mensajePorDefecto) {
		this.codigo = codigo;
		this.estadoHttp = estadoHttp;
		this.mensajePorDefecto = mensajePorDefecto;
	}

	/** Identificador estable que viaja en el campo {@code codigo} del sobre 2.5. */
	public String codigo() {
		return codigo;
	}

	/** Estado HTTP asociado al código (modelado como int: dominio sin framework). */
	public int estadoHttp() {
		return estadoHttp;
	}

	/** Mensaje humano por defecto, en español, apto para mostrar al usuario final. */
	public String mensajePorDefecto() {
		return mensajePorDefecto;
	}

	/**
	 * Resuelve el código canónico asociado a un estado HTTP, si existe.
	 *
	 * @param estadoHttp estado HTTP de la respuesta
	 * @return el código del catálogo, u {@link Optional#empty()} si el estado
	 *         no tiene representante canónico (p. ej. 405, 502)
	 */
	public static Optional<CodigoError> porEstadoHttp(int estadoHttp) {
		for (CodigoError valor : values()) {
			if (valor.estadoHttp == estadoHttp) {
				return Optional.of(valor);
			}
		}
		return Optional.empty();
	}

	/**
	 * Sintetiza un código estable para estados HTTP sin entrada canónica en el
	 * catálogo (p. ej. {@code 405 -> "GTW-405"}). El resultado es determinista
	 * y autodescriptivo, de modo que el frontend pueda conmutar sobre él aunque
	 * el catálogo aún no lo formalice.
	 *
	 * @param estadoHttp estado HTTP de la respuesta
	 * @return código canónico si existe; en caso contrario {@code "GTW-<estado>"}
	 */
	public static String codigoParaEstado(int estadoHttp) {
		return porEstadoHttp(estadoHttp)
				.map(CodigoError::codigo)
				.orElse(PREFIJO_GENERICO + estadoHttp);
	}
}
