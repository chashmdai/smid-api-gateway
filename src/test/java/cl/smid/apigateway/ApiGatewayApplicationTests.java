package cl.smid.apigateway;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Prueba de humo: verifica que el contexto completo de Spring arranca con todos
 * los beans cableados (cadena de filtros, decoder por kid, fuente CORS,
 * manejador global y filtro de auditoría).
 *
 * <p>El secreto se inyecta por la propiedad {@code JWT_SECRET} del propio test:
 * debe ser un literal (las anotaciones exigen constantes de compilación) y
 * alcanzar los 256 bits, o el {@code DecodificadorJwtPorKid} abortaría el
 * arranque por su validación de longitud mínima. Las demás variables usan los
 * valores por defecto de {@code application.yml}.</p>
 */
@SpringBootTest(properties = {
		"JWT_SECRET=clave-de-prueba-para-context-load-con-mas-de-256-bits-1234567890",
		"CORS_ALLOWED_ORIGINS=http://localhost:3000"
})
class ApiGatewayApplicationTests {

	@Test
	@DisplayName("El contexto de la aplicación carga sin errores")
	void contextLoads() {
		// Si el contexto no levantara (bean faltante, propiedad sin resolver,
		// clave JWT inválida), este método ni siquiera se ejecutaría.
	}
}
