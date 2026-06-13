package cl.smid.apigateway.api.error;

import cl.smid.apigateway.dominio.error.CodigoError;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Único punto de escritura del sobre de error unificado 2.5 en la respuesta
 * reactiva. Lo comparten los tres emisores de errores del Gateway:
 *
 * <ul>
 *   <li>el punto de entrada de autenticación (401 {@code AUTZ-003}),</li>
 *   <li>el manejador de acceso denegado (403 {@code AUTZ-004}),</li>
 *   <li>el {@code ManejadorGlobalExcepciones} ({@code GTW-xxx}).</li>
 * </ul>
 *
 * <p>Centralizar la serialización garantiza que NINGUNA respuesta de error
 * pueda divergir del contrato congelado (cierra la brecha B8 de la auditoría:
 * alineación del sobre entre servicios) y elimina la triplicación de código
 * que existía en el Gateway legado (SecurityConfig y el handler duplicaban
 * la lógica de escritura).</p>
 */
@Component
public class EscritorRespuestaError {

	private static final Logger log = LoggerFactory.getLogger(EscritorRespuestaError.class);

	/**
	 * Sobre mínimo de emergencia, preconstruido a mano, para el caso límite en
	 * que Jackson falle serializando (prácticamente imposible con un record de
	 * tipos simples, pero un Gateway jamás debe responder cuerpo vacío ante un
	 * error de su propio manejador de errores).
	 */
	private static final byte[] SOBRE_DE_EMERGENCIA = ("{"
			+ "\"status\":500,"
			+ "\"error\":\"Internal Server Error\","
			+ "\"codigo\":\"GTW-500\","
			+ "\"mensaje\":\"Error interno del API Gateway.\""
			+ "}").getBytes(StandardCharsets.UTF_8);

	/**
	 * Se inyecta el ObjectMapper auto-configurado por Spring Boot: ya registra
	 * JavaTimeModule y serializa Instant como ISO-8601 UTC (string), exactamente
	 * el formato del sobre vigente de smid-auth.
	 */
	private final ObjectMapper objectMapper;

	public EscritorRespuestaError(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}

	/**
	 * Escribe el sobre para un código canónico del catálogo, usando su estado
	 * HTTP y su mensaje por defecto.
	 *
	 * @param exchange intercambio reactivo de la petición en curso
	 * @param codigo   entrada canónica del catálogo de errores
	 * @return señal de finalización de la escritura de la respuesta
	 */
	@NonNull
	public Mono<Void> escribir(@NonNull ServerWebExchange exchange, @NonNull CodigoError codigo) {
		return escribir(exchange, codigo.estadoHttp(),
				Objects.requireNonNull(codigo.codigo(), "El código de error no puede ser null"),
				Objects.requireNonNull(codigo.mensajePorDefecto(),
						"El mensaje de error no puede ser null"));
	}

	/**
	 * Escribe el sobre con estado, código y mensaje explícitos. La frase de
	 * razón ({@code error}) se deriva del estado; la {@code ruta} se toma de la
	 * petición y el {@code timestamp} se fija al instante de escritura.
	 *
	 * @param exchange   intercambio reactivo de la petición en curso
	 * @param estadoHttp estado HTTP a responder
	 * @param codigo     código estable del sobre ({@code AUTZ-xxx} / {@code GTW-xxx})
	 * @param mensaje    mensaje humano en español
	 * @return señal de finalización de la escritura de la respuesta
	 */
	@NonNull
	public Mono<Void> escribir(@NonNull ServerWebExchange exchange, int estadoHttp,
			@NonNull String codigo, @NonNull String mensaje) {

		ServerHttpResponse respuesta = exchange.getResponse();

		// Si la respuesta ya fue confirmada al cliente no puede reescribirse:
		// registrar y terminar en silencio (comportamiento defensivo; los
		// llamadores que necesiten propagar el error lo verifican antes).
		if (respuesta.isCommitted()) {
			log.warn("Respuesta ya confirmada; no es posible escribir el sobre de error "
					+ "{} para la ruta {}", codigo, exchange.getRequest().getPath().value());
			return Objects.requireNonNull(Mono.empty(),
					"La señal vacía de respuesta no puede ser null");
		}

		ErrorResponse sobre = ErrorResponse.de(
				estadoHttp,
				frasePara(estadoHttp),
				codigo,
				mensaje,
				exchange.getRequest().getPath().value());

		byte[] cuerpo;
		HttpStatusCode estadoFinal = HttpStatusCode.valueOf(estadoHttp);
		try {
			cuerpo = Objects.requireNonNull(objectMapper.writeValueAsBytes(sobre),
					"El cuerpo serializado no puede ser null");
		}
		catch (JsonProcessingException ex) {
			// Degradación controlada: nunca responder sin cuerpo de error.
			log.error("Fallo serializando el sobre de error unificado; "
					+ "se responde el sobre de emergencia", ex);
			cuerpo = Objects.requireNonNull(SOBRE_DE_EMERGENCIA,
					"El sobre de emergencia no puede ser null");
			estadoFinal = HttpStatus.INTERNAL_SERVER_ERROR;
		}

		respuesta.setStatusCode(estadoFinal);
		respuesta.getHeaders().setContentType(MediaType.APPLICATION_JSON);

		DataBuffer buffer = Objects.requireNonNull(respuesta.bufferFactory().wrap(cuerpo),
				"El buffer de respuesta no puede ser null");
		return respuesta.writeWith(Objects.requireNonNull(Mono.just(buffer),
				"El publisher de respuesta no puede ser null"));
	}

	/**
	 * Frase de razón HTTP en inglés para el campo {@code error} del sobre
	 * (p. ej. {@code 401 -> "Unauthorized"}), con fallback genérico para
	 * estados no estándar.
	 */
	private String frasePara(int estadoHttp) {
		HttpStatus resuelto = HttpStatus.resolve(estadoHttp);
		return resuelto != null ? resuelto.getReasonPhrase() : "Error";
	}
}
