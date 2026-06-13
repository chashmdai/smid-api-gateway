package cl.smid.apigateway.api.error;

import cl.smid.apigateway.dominio.error.CodigoError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.net.UnknownHostException;
import java.util.Objects;
import java.util.Optional;

/**
 * Normalizador global de errores del Gateway: toda excepción que escape de la
 * cadena de filtros se traduce al sobre unificado 2.5 con un código estable
 * del catálogo (brecha B4 de la auditoría, Fase 2 del plan).
 *
 * <p><strong>Orden de evaluación del mapeo</strong> (primera coincidencia gana):</p>
 * <ol>
 *   <li>Respuesta ya confirmada → propagar (no se puede reescribir).</li>
 *   <li>{@link ResponseStatusException} → su estado, con código canónico o
 *       sintetizado ({@code GTW-<estado>}). Cubre el 404 de ruta no mapeada
 *       ({@code GTW-404}) y el 504 que Spring Cloud Gateway emite al vencer
 *       el {@code response-timeout} ({@code GTW-002}).</li>
 *   <li>Cadena de causas con {@link ConnectException} (incluye la
 *       {@code AnnotatedConnectException} de Netty) o
 *       {@link UnknownHostException} → 503 {@code GTW-001}: destino caído
 *       o irresoluble.</li>
 *   <li>Cadena de causas con un timeout ({@code java.util.concurrent} o
 *       {@code io.netty.handler.timeout}) → 504 {@code GTW-002}.</li>
 *   <li>Cualquier otra → 500 {@code GTW-500}; el detalle real queda en el log
 *       del servidor y JAMÁS se filtra al cliente (misma filosofía que el
 *       {@code AUTZ-500} de smid-auth).</li>
 * </ol>
 *
 * <p>Sobre el {@code @Order(-1)}: Boot registra su
 * {@code DefaultErrorWebExceptionHandler} solo con
 * {@code @ConditionalOnMissingBean(ErrorWebExceptionHandler.class)}; al existir
 * este bean, el manejador HTML por defecto retrocede por completo. El orden -1
 * además lo antepone al {@code WebFluxResponseStatusExceptionHandler}
 * (orden 0), que respondería sin cuerpo.</p>
 */
@Component
@Order(-1)
public class ManejadorGlobalExcepciones implements ErrorWebExceptionHandler {

	private static final Logger log = LoggerFactory.getLogger(ManejadorGlobalExcepciones.class);

	/** Tope de profundidad al recorrer causas: corta ciclos patológicos. */
	private static final int PROFUNDIDAD_MAXIMA_CAUSAS = 12;

	private final EscritorRespuestaError escritor;

	public ManejadorGlobalExcepciones(EscritorRespuestaError escritor) {
		this.escritor = escritor;
	}

	@Override
	@NonNull
	public Mono<Void> handle(@NonNull ServerWebExchange exchange, @NonNull Throwable ex) {

		// Si la respuesta ya viajó al cliente no hay nada que reescribir:
		// se propaga para que el contenedor cierre la conexión como corresponda.
		if (exchange.getResponse().isCommitted()) {
			return Objects.requireNonNull(Mono.error(ex),
					"La señal de error no puede ser null");
		}

		String ruta = exchange.getRequest().getPath().value();
		String requestId = exchange.getRequest().getHeaders().getFirst("X-Request-Id");

		// ------------------------------------------------------------------
		// 1) Excepciones que ya portan un estado HTTP (incluye NotFoundException
		//    de Spring Cloud Gateway y el 504 de response-timeout, que SCG
		//    envuelve en ResponseStatusException(GATEWAY_TIMEOUT)).
		// ------------------------------------------------------------------
		if (ex instanceof ResponseStatusException rse) {
			int estado = rse.getStatusCode().value();
			Optional<CodigoError> canonico = CodigoError.porEstadoHttp(estado);

			String codigo = canonico.map(CodigoError::codigo)
					.orElse(CodigoError.codigoParaEstado(estado));
			codigo = Objects.requireNonNull(codigo, "El código de error no puede ser null");

			// El reason de la excepción tiene prioridad; si no viene, se usa el
			// mensaje del catálogo (o uno genérico para códigos sintetizados).
			String razon = rse.getReason();
			String mensaje = (razon != null && !razon.isBlank())
					? razon
					: canonico.map(CodigoError::mensajePorDefecto)
							.orElse("La solicitud no pudo ser procesada por el Gateway.");
			mensaje = Objects.requireNonNull(mensaje, "El mensaje de error no puede ser null");

			registrar(estado, codigo, ruta, requestId, ex);
			return escritor.escribir(exchange, estado, codigo, mensaje);
		}

		// ------------------------------------------------------------------
		// 2) Destino caído: conexión rechazada (microservicio apagado o
		//    reiniciándose) o host irresoluble (DNS). 503 GTW-001.
		// ------------------------------------------------------------------
		if (causaContiene(ex, ConnectException.class)
				|| causaContiene(ex, UnknownHostException.class)) {
			registrar(CodigoError.GTW_001.estadoHttp(), CodigoError.GTW_001.codigo(),
					ruta, requestId, ex);
			return escritor.escribir(exchange, CodigoError.GTW_001);
		}

		// ------------------------------------------------------------------
		// 3) Timeout hacia el destino que no llegó envuelto en
		//    ResponseStatusException (cinturón y tirantes). 504 GTW-002.
		// ------------------------------------------------------------------
		if (causaContiene(ex, java.util.concurrent.TimeoutException.class)
				|| causaContiene(ex, io.netty.handler.timeout.TimeoutException.class)) {
			registrar(CodigoError.GTW_002.estadoHttp(), CodigoError.GTW_002.codigo(),
					ruta, requestId, ex);
			return escritor.escribir(exchange, CodigoError.GTW_002);
		}

		// ------------------------------------------------------------------
		// 4) Falla no clasificada: 500 GTW-500. El stacktrace completo queda
		//    en el log; el cliente recibe solo el mensaje genérico del catálogo.
		// ------------------------------------------------------------------
		log.error("[{}] Error interno no clasificado en el Gateway | ruta={} | codigo={}",
				requestIdParaLog(requestId), ruta, CodigoError.GTW_500.codigo(), ex);
		return escritor.escribir(exchange, CodigoError.GTW_500);
	}

	/**
	 * Recorre la cadena de causas (con tope de profundidad, defensa contra
	 * ciclos) buscando una excepción del tipo indicado o de un subtipo.
	 */
	private boolean causaContiene(Throwable raiz, Class<? extends Throwable> tipo) {
		Throwable actual = raiz;
		int profundidad = 0;
		while (actual != null && profundidad < PROFUNDIDAD_MAXIMA_CAUSAS) {
			if (tipo.isInstance(actual)) {
				return true;
			}
			actual = (actual.getCause() == actual) ? null : actual.getCause();
			profundidad++;
		}
		return false;
	}

	/**
	 * Bitácora con severidad proporcional al tipo de falla: los 5xx de
	 * infraestructura (503/504) son advertencias operativas esperables en un
	 * strangler; los 4xx son ruido de cliente (INFO); el 500 lo registra el
	 * llamador con stacktrace completo.
	 */
	private void registrar(int estado, String codigo, String ruta,
			String requestId, Throwable ex) {
		if (estado == 503 || estado == 504) {
			log.warn("[{}] Falla de destino | ruta={} | estado={} | codigo={} | causa={}",
					requestIdParaLog(requestId), ruta, estado, codigo, ex.toString());
		}
		else if (estado >= 500) {
			log.error("[{}] Error 5xx en el Gateway | ruta={} | estado={} | codigo={}",
					requestIdParaLog(requestId), ruta, estado, codigo, ex);
		}
		else {
			log.info("[{}] Respuesta de error a cliente | ruta={} | estado={} | codigo={}",
					requestIdParaLog(requestId), ruta, estado, codigo);
		}
	}

	private String requestIdParaLog(String requestId) {
		return (requestId != null && !requestId.isBlank()) ? requestId : "sin-request-id";
	}
}
