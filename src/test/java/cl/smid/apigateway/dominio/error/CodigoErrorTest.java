package cl.smid.apigateway.dominio.error;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pruebas del catálogo de códigos de error (dominio puro, sin framework).
 * Verifican la decisión D1 (prefijos {@code AUTZ-}/{@code GTW-}) y la síntesis
 * determinista de códigos para estados HTTP sin entrada canónica.
 */
class CodigoErrorTest {

	@Test
	@DisplayName("Cada código canónico expone el identificador, estado y mensaje esperados")
	void catalogoCanonico() {
		assertThat(CodigoError.AUTZ_003.codigo()).isEqualTo("AUTZ-003");
		assertThat(CodigoError.AUTZ_003.estadoHttp()).isEqualTo(401);

		assertThat(CodigoError.AUTZ_004.codigo()).isEqualTo("AUTZ-004");
		assertThat(CodigoError.AUTZ_004.estadoHttp()).isEqualTo(403);

		assertThat(CodigoError.GTW_001.codigo()).isEqualTo("GTW-001");
		assertThat(CodigoError.GTW_001.estadoHttp()).isEqualTo(503);

		assertThat(CodigoError.GTW_002.codigo()).isEqualTo("GTW-002");
		assertThat(CodigoError.GTW_002.estadoHttp()).isEqualTo(504);

		assertThat(CodigoError.GTW_404.codigo()).isEqualTo("GTW-404");
		assertThat(CodigoError.GTW_404.estadoHttp()).isEqualTo(404);

		assertThat(CodigoError.GTW_500.codigo()).isEqualTo("GTW-500");
		assertThat(CodigoError.GTW_500.estadoHttp()).isEqualTo(500);

		// Todos los mensajes por defecto están poblados (no se filtra null al sobre).
		for (CodigoError codigo : CodigoError.values()) {
			assertThat(codigo.mensajePorDefecto()).isNotBlank();
		}
	}

	@Test
	@DisplayName("porEstadoHttp resuelve el código canónico cuando existe")
	void porEstadoHttpResuelveCanonicos() {
		assertThat(CodigoError.porEstadoHttp(401)).contains(CodigoError.AUTZ_003);
		assertThat(CodigoError.porEstadoHttp(503)).contains(CodigoError.GTW_001);
		assertThat(CodigoError.porEstadoHttp(504)).contains(CodigoError.GTW_002);
	}

	@Test
	@DisplayName("porEstadoHttp devuelve vacío para estados sin representante canónico")
	void porEstadoHttpVacioParaNoCanonicos() {
		assertThat(CodigoError.porEstadoHttp(405)).isEqualTo(Optional.empty());
		assertThat(CodigoError.porEstadoHttp(418)).isEqualTo(Optional.empty());
	}

	@Test
	@DisplayName("codigoParaEstado usa el canónico si existe y sintetiza GTW-<estado> si no")
	void codigoParaEstadoSintetiza() {
		// Canónicos: devuelve el código del catálogo.
		assertThat(CodigoError.codigoParaEstado(404)).isEqualTo("GTW-404");
		assertThat(CodigoError.codigoParaEstado(503)).isEqualTo("GTW-001");

		// No canónicos: sintetiza un código estable y autodescriptivo.
		assertThat(CodigoError.codigoParaEstado(405)).isEqualTo("GTW-405");
		assertThat(CodigoError.codigoParaEstado(415)).isEqualTo("GTW-415");
		assertThat(CodigoError.codigoParaEstado(502)).isEqualTo("GTW-502");
	}
}
