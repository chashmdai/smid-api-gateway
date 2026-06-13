package cl.smid.apigateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

/**
 * Contrato JWT externalizado del Gateway ({@code smid.jwt.*}), enlazado por
 * constructor (record = inmutable). Cierra las brechas B1/B3 de la auditoría:
 *
 * <ul>
 *   <li>{@code claves} es el <strong>mapa kid → secreto</strong> que habilita
 *       la rotación sin caída (DT-3). En operación normal contiene una sola
 *       entrada; durante una ventana de rotación, dos (vigente + anterior).</li>
 *   <li>Los <strong>valores</strong> llegan SIEMPRE por variables de entorno
 *       ({@code JWT_SECRET}, {@code JWT_ISSUER}, {@code JWT_AUDIENCE}); este
 *       record no conoce ni un solo literal (DT-2).</li>
 * </ul>
 *
 * <p>La estructura espejea {@code PropiedadesJwt} de {@code smid-auth} con una
 * diferencia deliberada: aquí NO existe {@code kid-activo}, porque el Gateway
 * no firma tokens — solo los valida. El emisor decide con qué clave firma; el
 * validador debe aceptar todas las claves vigentes.</p>
 *
 * @param emisor    valor exacto que debe traer el claim {@code iss}
 *                  (contrato 2.4: {@code smid-auth})
 * @param audiencia valor que debe estar contenido en el claim {@code aud}
 *                  (contrato 2.4: {@code smid-servicios})
 * @param claves    mapa {@code kid → secreto HS256}; las claves del mapa son
 *                  los {@code kid} admitidos y los valores los secretos en
 *                  texto (≥ 32 bytes UTF-8 cada uno)
 */
@ConfigurationProperties(prefix = "smid.jwt")
public record PropiedadesJwt(
		String emisor,
		String audiencia,
		Map<String, String> claves) {

	/**
	 * Constructor compacto: copia defensiva e inmutable del mapa de claves.
	 * La validación SEMÁNTICA (mapa no vacío, longitud mínima de los
	 * secretos, emisor/audiencia no blancos) vive en
	 * {@code DecodificadorJwtPorKid#crear}, que es el único consumidor y el
	 * punto donde un fallo aborta el arranque con un mensaje accionable.
	 */
	public PropiedadesJwt {
		claves = claves == null ? Map.of() : Map.copyOf(claves);
	}
}
