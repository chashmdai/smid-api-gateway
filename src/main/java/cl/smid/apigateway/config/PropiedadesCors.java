package cl.smid.apigateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Configuración CORS externalizada del Gateway ({@code smid.cors.*}). Cierra la
 * brecha B5 de la auditoría: los orígenes permitidos dejan de estar
 * <em>hardcodeados</em> (en el legado convivían {@code localhost:3000} y una IP
 * de servidor escritas en código) y pasan a gobernarse por entorno (DT-7).
 *
 * <p>La variable {@code CORS_ALLOWED_ORIGINS} se declara en {@code application.yml}
 * como una lista separada por comas; el <em>relaxed binding</em> de Spring Boot
 * la convierte en esta {@link List}. Ejemplo de producción:</p>
 *
 * <pre>{@code CORS_ALLOWED_ORIGINS=https://app.defensorianinez.cl,https://admin.defensorianinez.cl}</pre>
 *
 * <p>El Gateway es el <strong>único</strong> punto donde se resuelve CORS de
 * todo el ecosistema (mecanismo conservado de la auditoría §3): los servicios
 * downstream nunca ven una petición preflight, porque viven detrás del Gateway.</p>
 *
 * @param origenesPermitidos orígenes HTTP exactos autorizados a invocar la API
 *                           (esquema + host + puerto); nunca {@code "*"} junto
 *                           con credenciales, combinación que el navegador
 *                           rechaza y que el contrato de seguridad prohíbe
 */
@ConfigurationProperties(prefix = "smid.cors")
public record PropiedadesCors(List<String> origenesPermitidos) {

	/**
	 * Constructor compacto: copia defensiva e inmutable. Si no se define la
	 * variable, la lista queda vacía y el Gateway no autoriza ningún origen
	 * cruzado (postura segura por defecto: mejor negar que abrir de más).
	 */
	public PropiedadesCors {
		origenesPermitidos = origenesPermitidos == null
				? List.of()
				: List.copyOf(origenesPermitidos);
	}
}
