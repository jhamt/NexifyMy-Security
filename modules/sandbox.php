<?php
/**
 * Shadow Runtime (Serverless Sandbox) Module
 *
 * Provides process-isolated code execution via recursive self-requests.
 * No external servers, no Docker, no LXC — pure WordPress/PHP.
 *
 * @package NexifyMy_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( 'Direct access denied.' );
}

/**
 * Class NexifyMy_Security_Sandbox
 *
 * Public API:
 *   ::execute( $code, $options )  — Run code in the shadow process.
 *   ::analyze_code( $code )       — Static analysis without execution.
 *
 * The class follows the existing SentinelWP static singleton pattern.
 */
class NexifyMy_Security_Sandbox {

	/*
	================================================================
	 *  CONSTANTS
	 * ============================================================= */

	/** @var string Query parameter that identifies a shadow request. */
	const SHADOW_PARAM = 'nexifymy_shadow_exec';

	/** @var string HTTP header carrying the one-time token. */
	const TOKEN_HEADER = 'X-NexifyMy-Shadow-Token';

	/** @var string HTTP header carrying the payload reference ID. */
	const PAYLOAD_HEADER = 'X-NexifyMy-Payload-ID';

	/** @var string Transient prefix for stored payloads. */
	const PAYLOAD_PREFIX = 'nexifymy_sbx_payload_';

	/** @var string Transient prefix for one-time tokens. */
	const TOKEN_PREFIX = 'nexifymy_sbx_token_';

	/** @var string DB savepoint name. */
	const SAVEPOINT_NAME = 'nexifymy_sandbox_sp';

	/** @var int Maximum code string length (bytes). */
	const MAX_CODE_LENGTH = 65536; // 64 KB

	/** @var int Default execution timeout (seconds). */
	const DEFAULT_TIMEOUT = 5;

	/** @var int Token time-to-live (seconds). */
	const TOKEN_TTL = 30;

	/** @var int Maximum output capture (bytes). */
	const MAX_OUTPUT_LENGTH = 131072; // 128 KB

	/** @var string Default Docker image for isolated execution. */
	const DOCKER_IMAGE = 'php:8.1-cli';

	/** @var string Docker container memory limit. */
	const DOCKER_MEMORY_LIMIT = '128m';

	/** @var float Docker container CPU limit (cores). */
	const DOCKER_CPU_LIMIT = 0.5;

	/*
	================================================================
	 *  PROPERTIES
	 * ============================================================= */

	/** @var bool */
	private static bool $initialised = false;

	/** @var array|null */
	private static ?array $settings_cache = null;

	/** @var array Errors captured by the shadow error handler. */
	private static array $captured_errors = array();

	/** @var bool Whether we are currently inside a shadow process. */
	private static bool $is_shadow = false;

	/** @var bool|null Cached Docker availability detection result. */
	private static ?bool $docker_available = null;

	/**
	 * Forbidden functions — categorised for reporting.
	 *
	 * @var array<string, string[]>
	 */
	const FORBIDDEN_FUNCTIONS = array(
		'code_execution'         => array(
			'exec',
			'shell_exec',
			'system',
			'passthru',
			'popen',
			'proc_open',
			'pcntl_exec',
			'dl',
			'putenv',
		),
		'file_system'            => array(
			'file_put_contents',
			'fwrite',
			'fputs',
			'fopen',
			'unlink',
			'rmdir',
			'rename',
			'copy',
			'mkdir',
			'chmod',
			'chown',
			'chgrp',
			'symlink',
			'link',
			'tempnam',
			'tmpfile',
			'move_uploaded_file',
		),
		'network'                => array(
			'curl_exec',
			'curl_multi_exec',
			'fsockopen',
			'pfsockopen',
			'stream_socket_client',
			'stream_socket_server',
		),
		'wordpress_auth'         => array(
			'wp_set_auth_cookie',
			'wp_set_current_user',
			'wp_create_user',
			'wp_insert_user',
			'wp_update_user',
			'wp_delete_user',
			'wp_set_password',
			'grant_super_admin',
			'revoke_super_admin',
		),
		'database_direct'        => array(
			'mysql_query',
			'mysqli_query',
			'pg_query',
		),
		'dangerous_php'          => array(
			'eval',
			'assert',
			'preg_replace_callback',
			'create_function',
			'call_user_func',
			'call_user_func_array',
			'ReflectionFunction',
		),
		'information_disclosure' => array(
			'phpinfo',
			'getenv',
			'get_defined_vars',
			'get_defined_functions',
			'get_defined_constants',
		),
	);

	/*
	================================================================
	 *  1. INITIALISATION
	 * ============================================================= */

	/**
	 * Bootstrap the Sandbox module.
	 *
	 * Must be called AFTER Logger and Firewall are loaded.
	 *
	 * @return void
	 */
	public static function init(): void {

		if ( self::$initialised ) {
			return;
		}
		self::$initialised = true;

		$settings = self::get_settings();

		if ( empty( $settings['sandbox_enabled'] ) ) {
			return;
		}

		/*
		 * Listen for inbound shadow requests VERY early.
		 * `plugins_loaded` at priority 0 ensures our classes exist
		 * but themes/templates haven't loaded yet.
		 */
		add_action( 'plugins_loaded', array( __CLASS__, 'maybe_handle_shadow_request' ), 0 );

		/*
		 * Register the AJAX endpoint for the admin Sandbox Console.
		 */
		add_action( 'wp_ajax_nexifymy_test_in_sandbox', array( __CLASS__, 'ajax_sandbox_console' ) );
	}

	/*
	================================================================
	 *  2. PUBLIC API — EXECUTE
	 * ============================================================= */

	/**
	 * Execute PHP code inside the Shadow Runtime.
	 *
	 * This is the primary public interface. It:
	 *   1. Validates and stores the payload.
	 *   2. Generates a one-time HMAC token.
	 *   3. Fires a self-request to an isolated PHP process.
	 *   4. Parses and returns the result envelope.
	 *
	 * @param  string $code    PHP code to execute (WITHOUT <?php tags).
	 * @param  array  $options {
	 *     Optional. Execution options.
	 *
	 *     @type int    $timeout        Max seconds (default 5).
	 *     @type bool   $preview        Always rollback DB changes (default true).
	 *     @type array  $context        Variables to inject into execution scope.
	 *     @type bool   $static_only    Only run static analysis, skip execution.
	 *     @type string $label          Human-readable label for logging.
	 * }
	 * @return array {
	 *     Execution result envelope.
	 *
	 *     @type bool   $success        Whether execution completed without fatal errors.
	 *     @type string $output         Captured stdout (echo/print).
	 *     @type mixed  $return_value   The value returned by the code (if any).
	 *     @type array  $errors         Array of captured errors/warnings.
	 *     @type array  $queries        Array of DB queries attempted.
	 *     @type array  $forbidden      Forbidden function calls detected (static analysis).
	 *     @type float  $execution_time Seconds elapsed.
	 *     @type int    $memory_peak    Peak memory usage (bytes).
	 *     @type string $status         'completed' | 'timeout' | 'fatal' | 'blocked'.
	 * }
	 */
	public static function execute( string $code, array $options = array() ): array {

		$defaults = array(
			'timeout'     => self::DEFAULT_TIMEOUT,
			'preview'     => true,
			'context'     => array(),
			'static_only' => false,
			'label'       => 'Sandbox execution',
		);

		$options = wp_parse_args( $options, $defaults );

		// ── Empty result envelope ──────────────────────────────────
		$result = self::empty_result_envelope();

		// ── Input validation ───────────────────────────────────────
		if ( empty( trim( $code ) ) ) {
			$result['status']   = 'blocked';
			$result['errors'][] = array(
				'type'    => 'validation',
				'message' => 'No code provided.',
			);
			return $result;
		}

		if ( strlen( $code ) > self::MAX_CODE_LENGTH ) {
			$result['status']   = 'blocked';
			$result['errors'][] = array(
				'type'    => 'validation',
				'message' => sprintf( 'Code exceeds maximum length (%s bytes).', number_format( self::MAX_CODE_LENGTH ) ),
			);
			return $result;
		}

		// ── Static analysis (always runs first) ───────────────────
		$forbidden           = self::detect_forbidden_calls( $code );
		$result['forbidden'] = $forbidden;

		if ( ! empty( $forbidden ) ) {
			self::log(
				'sandbox_forbidden_detected',
				sprintf(
					'Static analysis found %d forbidden call(s) in: %s',
					count( $forbidden, COUNT_RECURSIVE ) - count( $forbidden ),
					$options['label']
				),
				'high',
				array(
					'forbidden'    => $forbidden,
					'code_preview' => substr( $code, 0, 500 ),
				)
			);
		}

		// If static-only mode or forbidden calls found, skip dynamic execution.
		if ( $options['static_only'] ) {
			$result['success'] = true;
			$result['status']  = 'static_only';
			return $result;
		}

		// ── Docker isolation (preferred when enabled and available) ─
		$settings = self::get_settings();

		if ( ! empty( $settings['sandbox_prefer_docker'] ) && self::detect_docker_availability() ) {

			$docker_result = self::execute_in_docker(
				$code,
				$options['context'],
				intval( $options['timeout'] ),
				$options['preview']
			);

			$docker_result['forbidden'] = $forbidden;

			self::log(
				'sandbox_docker_complete',
				sprintf(
					'Docker execution: %s (status: %s, time: %ss)',
					$options['label'],
					$docker_result['status'],
					$docker_result['execution_time']
				),
				'info',
				array(
					'status'         => $docker_result['status'],
					'execution_time' => $docker_result['execution_time'],
					'isolation'      => 'docker',
				)
			);

			return $docker_result;
		}

		// ── Prepare payload ────────────────────────────────────────
		$payload_id = wp_generate_uuid4();

		$payload = array(
			'id'      => $payload_id,
			'code'    => $code,
			'context' => $options['context'],
			'preview' => $options['preview'],
			'label'   => $options['label'],
			'created' => microtime( true ),
			'origin'  => self::get_client_ip(),
		);

		// Store payload in transient — it never leaves the server.
		$stored = set_transient(
			self::PAYLOAD_PREFIX . $payload_id,
			$payload,
			self::TOKEN_TTL
		);

		if ( ! $stored ) {
			$result['status']   = 'fatal';
			$result['errors'][] = array(
				'type'    => 'system',
				'message' => 'Failed to store sandbox payload.',
			);
			return $result;
		}

		// ── Generate one-time HMAC token ───────────────────────────
		$token = self::generate_token( $payload_id );

		// Store the token for verification in the shadow process.
		set_transient(
			self::TOKEN_PREFIX . $payload_id,
			array(
				'hash'      => hash( 'sha256', $token ),
				'origin_ip' => self::get_server_ip(),
				'created'   => time(),
			),
			self::TOKEN_TTL
		);

		// ── Fire the self-request ──────────────────────────────────
		$target_url = add_query_arg(
			array( self::SHADOW_PARAM => '1' ),
			home_url( '/' )
		);

		self::log(
			'sandbox_execute_start',
			sprintf( 'Starting shadow execution: %s (payload: %s)', $options['label'], $payload_id ),
			'info',
			array(
				'payload_id' => $payload_id,
				'timeout'    => $options['timeout'],
			)
		);

		$start_time = microtime( true );

		$response = wp_remote_post(
			$target_url,
			array(
				'timeout'     => max( 2, intval( $options['timeout'] ) + 2 ), // +2s buffer
				'redirection' => 0,
				'httpversion' => '1.1',
				'blocking'    => true,
				'sslverify'   => false, // Same server — self-signed certs are common locally.
				'headers'     => array(
					'Content-Type'       => 'application/json',
					self::TOKEN_HEADER   => $token,
					self::PAYLOAD_HEADER => $payload_id,
					'X-NexifyMy-Shadow'  => '1',
					'User-Agent'         => 'SentinelWP-Shadow/1.0',
				),
				'body'        => wp_json_encode(
					array(
						'action'     => 'execute',
						'payload_id' => $payload_id,
						'timeout'    => intval( $options['timeout'] ),
					)
				),
				'cookies'     => array(), // Don't forward session cookies.
			)
		);

		$elapsed = microtime( true ) - $start_time;

		// ── Clean up transients ────────────────────────────────────
		delete_transient( self::PAYLOAD_PREFIX . $payload_id );
		delete_transient( self::TOKEN_PREFIX . $payload_id );

		// ── Parse the response ─────────────────────────────────────
		if ( is_wp_error( $response ) ) {

			$error_msg = $response->get_error_message();

			$result['status']         = 'fatal';
			$result['execution_time'] = round( $elapsed, 4 );
			$result['errors'][]       = array(
				'type'    => 'http',
				'message' => $error_msg,
			);

			// Timeout detection.
			if ( stripos( $error_msg, 'timed out' ) !== false ||
				stripos( $error_msg, 'timeout' ) !== false ) {
				$result['status'] = 'timeout';
			}

			self::log(
				'sandbox_execute_failed',
				sprintf( 'Shadow request failed: %s', $error_msg ),
				'warning',
				array(
					'payload_id' => $payload_id,
					'error'      => $error_msg,
				)
			);

			return $result;
		}

		$http_code = wp_remote_retrieve_response_code( $response );
		$body      = wp_remote_retrieve_body( $response );

		// A 500 means the shadow process hit a fatal error.
		if ( $http_code >= 500 ) {
			$result['status']         = 'fatal';
			$result['execution_time'] = round( $elapsed, 4 );
			$result['output']         = substr( $body, 0, self::MAX_OUTPUT_LENGTH );
			$result['errors'][]       = array(
				'type'    => 'fatal',
				'message' => sprintf( 'Shadow process returned HTTP %d.', $http_code ),
			);

			self::log(
				'sandbox_fatal_error',
				sprintf( 'Shadow process fatal error (HTTP %d) for: %s', $http_code, $options['label'] ),
				'high',
				array(
					'payload_id' => $payload_id,
					'http_code'  => $http_code,
				)
			);

			return $result;
		}

		// Parse JSON envelope from the shadow process.
		$shadow_result = json_decode( $body, true );

		if ( ! is_array( $shadow_result ) || empty( $shadow_result['_sentinel_shadow'] ) ) {
			$result['status']         = 'fatal';
			$result['execution_time'] = round( $elapsed, 4 );
			$result['errors'][]       = array(
				'type'    => 'parse',
				'message' => 'Invalid response from shadow process.',
				'raw'     => substr( $body, 0, 1024 ),
			);
			return $result;
		}

		// ── Merge shadow results into our envelope ─────────────────
		$result['success']        = ! empty( $shadow_result['success'] );
		$result['output']         = isset( $shadow_result['output'] ) ? $shadow_result['output'] : '';
		$result['return_value']   = $shadow_result['return_value'] ?? null;
		$result['errors']         = array_merge( $result['errors'], $shadow_result['errors'] ?? array() );
		$result['queries']        = $shadow_result['queries'] ?? array();
		$result['execution_time'] = $shadow_result['execution_time'] ?? round( $elapsed, 4 );
		$result['memory_peak']    = $shadow_result['memory_peak'] ?? 0;
		$result['status']         = $shadow_result['status'] ?? 'completed';

		self::log(
			'sandbox_execute_complete',
			sprintf(
				'Shadow execution completed: %s (status: %s, time: %ss, queries: %d)',
				$options['label'],
				$result['status'],
				$result['execution_time'],
				count( $result['queries'] )
			),
			'info',
			array(
				'payload_id'     => $payload_id,
				'status'         => $result['status'],
				'execution_time' => $result['execution_time'],
				'error_count'    => count( $result['errors'] ),
				'query_count'    => count( $result['queries'] ),
			)
		);

		return $result;
	}

	/**
	 * Return a blank result envelope with all expected keys.
	 *
	 * @return array
	 */
	private static function empty_result_envelope(): array {
		return array(
			'success'        => false,
			'output'         => '',
			'return_value'   => null,
			'errors'         => array(),
			'queries'        => array(),
			'forbidden'      => array(),
			'execution_time' => 0.0,
			'memory_peak'    => 0,
			'status'         => 'pending',
		);
	}

	/*
	================================================================
	 *  3. SHADOW PROCESS — INBOUND HANDLER
	 * ============================================================= */

	/**
	 * Early hook: detect and handle incoming shadow requests.
	 *
	 * Hooked to: `plugins_loaded` @ priority 0.
	 *
	 * @return void
	 */
	public static function maybe_handle_shadow_request(): void {

		// Quick bail — is this a shadow request?
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET[ self::SHADOW_PARAM ] ) ) {
			return;
		}

		// Read headers.
		$token      = self::get_request_header( self::TOKEN_HEADER );
		$payload_id = self::get_request_header( self::PAYLOAD_HEADER );

		if ( empty( $token ) || empty( $payload_id ) ) {
			self::shadow_die( 'Missing authentication headers.', 403 );
		}

		// Mark ourselves as running inside a shadow process.
		self::$is_shadow = true;

		// Handle the request (this will die() at the end).
		self::handle_shadow_request( $token, $payload_id );
	}

	/**
	 * Main shadow-process handler.
	 *
	 * Runs inside the isolated PHP process. Verifies authentication,
	 * retrieves the payload, executes it, captures results, rolls back
	 * DB changes, and returns a JSON response.
	 *
	 * @param  string $token      The HMAC token.
	 * @param  string $payload_id The payload UUID.
	 * @return never              Always terminates via die().
	 */
	private static function handle_shadow_request( string $token, string $payload_id ): void {

		// ── 1. Verify the one-time token ───────────────────────────
		$verification = self::verify_token( $token, $payload_id );

		if ( is_wp_error( $verification ) ) {
			self::log(
				'sandbox_auth_failed',
				sprintf( 'Shadow auth failed: %s', $verification->get_error_message() ),
				'warning',
				array(
					'payload_id' => $payload_id,
					'ip'         => self::get_client_ip(),
				)
			);
			self::shadow_die( 'Authentication failed.', 403 );
		}

		// ── 2. Retrieve the payload ────────────────────────────────
		$payload = get_transient( self::PAYLOAD_PREFIX . $payload_id );

		if ( empty( $payload ) || ! is_array( $payload ) ) {
			self::shadow_die( 'Payload not found or expired.', 404 );
		}

		// Immediately delete both transients (one-time use).
		delete_transient( self::PAYLOAD_PREFIX . $payload_id );
		delete_transient( self::TOKEN_PREFIX . $payload_id );

		// ── 3. Read the payload ────────────────────────────────────
		$code    = $payload['code'] ?? '';
		$context = $payload['context'] ?? array();
		$preview = $payload['preview'] ?? true;
		$label   = $payload['label'] ?? 'unknown';

		// Read timeout from the POST body.
		$input_body = json_decode( file_get_contents( 'php://input' ), true );
		$timeout    = isset( $input_body['timeout'] ) ? intval( $input_body['timeout'] ) : self::DEFAULT_TIMEOUT;
		$timeout    = max( 1, min( 30, $timeout ) ); // clamp 1–30s

		// ── 4. Set execution limits ────────────────────────────────
        // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		@set_time_limit( $timeout + 2 );

		// ── 5. Install error & shutdown handlers ───────────────────
		self::$captured_errors = array();

		set_error_handler( array( __CLASS__, 'shadow_error_handler' ), E_ALL );

		register_shutdown_function( array( __CLASS__, 'shadow_shutdown_handler' ), $payload_id );

		// ── 6. Execute the code ────────────────────────────────────
		$result = self::execute_in_shadow( $code, $context, $timeout, $preview );

		// ── 7. Return JSON response ────────────────────────────────
		self::shadow_respond( $result, 200 );
	}

	/**
	 * Execute code within the shadow process scope.
	 *
	 * Sets up DB savepoint, output buffering, query monitoring, and
	 * runs the code via eval().
	 *
	 * @param  string $code    PHP code to execute.
	 * @param  array  $context Variables to extract into execution scope.
	 * @param  int    $timeout Timeout in seconds.
	 * @param  bool   $preview Whether to rollback DB changes.
	 * @return array           Shadow result array.
	 */
	private static function execute_in_shadow( string $code, array $context, int $timeout, bool $preview ): array {

		global $wpdb;

		$result = array(
			'_sentinel_shadow' => true,
			'success'          => false,
			'output'           => '',
			'return_value'     => null,
			'errors'           => array(),
			'queries'          => array(),
			'execution_time'   => 0.0,
			'memory_peak'      => 0,
			'status'           => 'pending',
		);

		// ── Enable query logging ───────────────────────────────────
		$original_savequeries = defined( 'SAVEQUERIES' ) && SAVEQUERIES;
		$query_start_index    = 0;

		if ( ! $original_savequeries ) {
			// We can't define SAVEQUERIES at runtime, but we CAN
			// hook into the query filter to capture queries manually.
		}

		// Capture queries via the `query` filter.
		$captured_queries = array();
		$query_monitor    = function ( string $query ) use ( &$captured_queries ): string {
			$captured_queries[] = array(
				'sql'  => $query,
				'time' => microtime( true ),
			);
			return $query;
		};

		add_filter( 'query', $query_monitor );

		// ── DB Savepoint ───────────────────────────────────────────
		$savepoint_created = false;

		if ( $preview ) {
			$savepoint_created = self::create_db_savepoint();
		}

		// ── Start output buffering ─────────────────────────────────
		ob_start();

		$start_time   = microtime( true );
		$start_memory = memory_get_usage( true );

		// ── Deadline enforcement via pcntl_alarm (if available) ────
		$alarm_set = false;
		if ( function_exists( 'pcntl_alarm' ) && function_exists( 'pcntl_signal' ) ) {
            // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			@pcntl_signal(
				SIGALRM,
				function () {
					throw new \RuntimeException( 'Sandbox execution timeout (SIGALRM).' );
				}
			);
            // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			@pcntl_alarm( $timeout );
			$alarm_set = true;
		}

		// ── Execute ────────────────────────────────────────────────
		try {

			/*
			 * Extract context variables into the local scope.
			 * Keys become variable names: ['foo' => 'bar'] → $foo = 'bar'.
			 */
			if ( ! empty( $context ) && is_array( $context ) ) {
                // phpcs:ignore WordPress.PHP.DontExtract.extract_extract
				extract( $context, EXTR_PREFIX_ALL, 'ctx' );
			}

			/*
			 * The code is evaluated here. Because this runs in a
			 * SEPARATE PHP PROCESS, a fatal error will only crash
			 * this shadow process — the parent stays alive and
			 * receives an HTTP 500.
			 */
			$return_value = eval( $code ); // phpcs:ignore Squiz.PHP.Eval.Discouraged

			$result['return_value'] = self::sanitize_return_value( $return_value );
			$result['success']      = true;
			$result['status']       = 'completed';

		} catch ( \Throwable $e ) {

			$result['success']  = false;
			$result['status']   = 'exception';
			$result['errors'][] = array(
				'type'    => get_class( $e ),
				'message' => $e->getMessage(),
				'file'    => basename( $e->getFile() ),
				'line'    => $e->getLine(),
			);
		}

		// ── Cancel alarm ───────────────────────────────────────────
		if ( $alarm_set ) {
            // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			@pcntl_alarm( 0 );
		}

		// ── Capture output ─────────────────────────────────────────
		$output = ob_get_clean();
		if ( $output === false ) {
			$output = '';
		}
		$result['output'] = substr( $output, 0, self::MAX_OUTPUT_LENGTH );

		// ── Timing & memory ────────────────────────────────────────
		$result['execution_time'] = round( microtime( true ) - $start_time, 6 );
		$result['memory_peak']    = memory_get_peak_usage( true );

		// ── Capture queries ────────────────────────────────────────
		remove_filter( 'query', $query_monitor );

		$result['queries'] = array_map(
			function ( array $q ) use ( $start_time ): array {
				return array(
					'sql'     => substr( $q['sql'], 0, 2048 ),
					'elapsed' => round( $q['time'] - ( $q['time'] > 1e9 ? $q['time'] : 0 ), 6 ),
				);
			},
			$captured_queries
		);

		// ── Append any errors captured by our handler ──────────────
		if ( ! empty( self::$captured_errors ) ) {
			$result['errors'] = array_merge( $result['errors'], self::$captured_errors );
		}

		// ── DB Rollback ────────────────────────────────────────────
		if ( $savepoint_created ) {
			self::rollback_db_savepoint();
		}

		// ── Analyze queries for dangerous operations ───────────────
		$result['query_analysis'] = self::analyze_captured_queries( $result['queries'] );

		return $result;
	}

	/*
	================================================================
	 *  4. TOKEN MANAGEMENT
	 * ============================================================= */

	/**
	 * Generate a one-time HMAC token for a payload.
	 *
	 * @param  string $payload_id The payload UUID.
	 * @return string             The hex-encoded HMAC token.
	 */
	private static function generate_token( string $payload_id ): string {

		$secret = self::get_token_secret();
		$data   = implode(
			'|',
			array(
				$payload_id,
				self::get_server_ip(),
				time(),
				wp_generate_password( 16, false ),
			)
		);

		return hash_hmac( 'sha256', $data, $secret );
	}

	/**
	 * Verify a shadow request token.
	 *
	 * Checks:
	 *   1. Token exists in transient store.
	 *   2. HMAC hash matches.
	 *   3. Request originated from same server IP.
	 *   4. Token hasn't expired (TTL enforced by transient).
	 *
	 * @param  string $token      The token from the request header.
	 * @param  string $payload_id The payload ID from the request header.
	 * @return true|WP_Error      True on success, WP_Error on failure.
	 */
	private static function verify_token( string $token, string $payload_id ) {

		$stored = get_transient( self::TOKEN_PREFIX . $payload_id );

		if ( empty( $stored ) || ! is_array( $stored ) ) {
			return new \WP_Error( 'token_missing', 'Token not found or expired.' );
		}

		// Verify hash.
		$expected_hash = $stored['hash'];
		$actual_hash   = hash( 'sha256', $token );

		if ( ! hash_equals( $expected_hash, $actual_hash ) ) {
			return new \WP_Error( 'token_mismatch', 'Token hash verification failed.' );
		}

		// Verify origin IP (prevent SSRF — request must come from this server).
		$request_ip = self::get_client_ip();
		$server_ip  = $stored['origin_ip'];

		// Allow loopback and same-server IPs.
		$allowed_ips = array(
			$server_ip,
			'127.0.0.1',
			'::1',
			'0.0.0.0',
		);

		// Also allow the server's public IP hitting itself.
		$additional_server_ip = isset( $_SERVER['SERVER_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) : '';
		if ( ! empty( $additional_server_ip ) ) {
			$allowed_ips[] = $additional_server_ip;
		}

		$ip_valid = false;
		foreach ( $allowed_ips as $allowed ) {
			if ( $request_ip === $allowed ) {
				$ip_valid = true;
				break;
			}
		}

		if ( ! $ip_valid ) {
			return new \WP_Error(
				'ip_mismatch',
				sprintf( 'Request IP %s does not match server IP.', $request_ip )
			);
		}

		// Verify age.
		if ( isset( $stored['created'] ) && ( time() - $stored['created'] ) > self::TOKEN_TTL ) {
			return new \WP_Error( 'token_expired', 'Token has expired.' );
		}

		return true;
	}

	/**
	 * Derive the secret key for HMAC token generation.
	 *
	 * @return string
	 */
	private static function get_token_secret(): string {

		$salt = defined( 'AUTH_SALT' ) ? AUTH_SALT : 'nexifymy_default_salt';

		return hash( 'sha256', $salt . '|sentinel_shadow_runtime|' . ABSPATH );
	}

	/*
	================================================================
	 *  5. DATABASE SAVEPOINT
	 * ============================================================= */

	/**
	 * Create a database savepoint within a transaction.
	 *
	 * All queries executed between create and rollback will be undone.
	 * Only works with InnoDB tables (standard for WordPress).
	 *
	 * @return bool True if savepoint was created successfully.
	 */
	private static function create_db_savepoint(): bool {

		global $wpdb;

        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
        // phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( 'SET autocommit = 0' );
		$wpdb->query( 'START TRANSACTION' );
		$result = $wpdb->query( 'SAVEPOINT ' . self::SAVEPOINT_NAME );
        // phpcs:enable

		if ( $result === false ) {
			self::log(
				'sandbox_savepoint_failed',
				'Failed to create DB savepoint.',
				'warning'
			);
			return false;
		}

		return true;
	}

	/**
	 * Rollback to the savepoint, undoing all DB changes.
	 *
	 * @return bool True if rollback succeeded.
	 */
	private static function rollback_db_savepoint(): bool {

		global $wpdb;

        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
        // phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( 'ROLLBACK TO SAVEPOINT ' . self::SAVEPOINT_NAME );
		$wpdb->query( 'COMMIT' );
		$wpdb->query( 'SET autocommit = 1' );
        // phpcs:enable

		return true;
	}

	/*
	================================================================
	 *  6. STATIC ANALYSIS — FORBIDDEN FUNCTION DETECTION
	 * ============================================================= */

	/**
	 * Statically analyze code for forbidden function calls.
	 *
	 * Uses token-aware pattern matching to reduce false positives
	 * (e.g., won't flag "system" inside a string comment about systems).
	 *
	 * @param  string $code The PHP code to analyze.
	 * @return array        Keyed by category, each containing matched functions.
	 */
	public static function detect_forbidden_calls( string $code ): array {

		$findings = array();

		// Strip comments to reduce false positives.
		$clean_code = self::strip_php_comments( $code );

		foreach ( self::FORBIDDEN_FUNCTIONS as $category => $functions ) {
			foreach ( $functions as $func ) {
				/*
				 * Match the function name followed by `(` with optional
				 * whitespace, but NOT preceded by `->` or `::` or `$`
				 * (to avoid matching method calls with the same name).
				 *
				 * Also check for string-based invocation:
				 *   $f = 'exec'; $f(...);
				 *   call_user_func('exec', ...);
				 *   'exec'(...)  — PHP 8.1+ first-class callables
				 */
				$pattern = '/(?<![>\w\$:])' . preg_quote( $func, '/' ) . '\s*\(/i';

				if ( preg_match( $pattern, $clean_code ) ) {
					if ( ! isset( $findings[ $category ] ) ) {
						$findings[ $category ] = array();
					}
					$findings[ $category ][] = $func;
				}

				// Also check for string-based invocation.
				$string_patterns = array(
					'/["\']' . preg_quote( $func, '/' ) . '["\']\s*\(/i',
					'/call_user_func\w*\s*\(\s*["\']' . preg_quote( $func, '/' ) . '/i',
				);

				foreach ( $string_patterns as $sp ) {
					if ( preg_match( $sp, $clean_code ) && ! in_array( $func, $findings[ $category ] ?? array(), true ) ) {
						if ( ! isset( $findings[ $category ] ) ) {
							$findings[ $category ] = array();
						}
						$findings[ $category ][] = $func . ' (string invocation)';
					}
				}
			}
		}

		return $findings;
	}

	/**
	 * Analyze the captured DB queries for dangerous operations.
	 *
	 * @param  array $queries Array of [ 'sql' => ..., 'elapsed' => ... ].
	 * @return array          Analysis results.
	 */
	private static function analyze_captured_queries( array $queries ): array {

		global $wpdb;

		$analysis = array(
			'total_queries'     => count( $queries ),
			'write_queries'     => 0,
			'dangerous_queries' => array(),
			'tables_affected'   => array(),
		);

		$dangerous_tables = array(
			$wpdb->users,
			$wpdb->usermeta,
			$wpdb->options,
		);

		$write_keywords = array( 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'TRUNCATE', 'CREATE', 'REPLACE' );

		foreach ( $queries as $q ) {
			$sql_upper = strtoupper( trim( $q['sql'] ) );

			// Detect write operations.
			foreach ( $write_keywords as $kw ) {
				if ( strpos( $sql_upper, $kw ) === 0 ) {
					++$analysis['write_queries'];

					// Check against dangerous tables.
					foreach ( $dangerous_tables as $table ) {
						if ( stripos( $q['sql'], $table ) !== false ) {
							$analysis['dangerous_queries'][] = array(
								'sql'    => $q['sql'],
								'reason' => sprintf( 'Write to sensitive table: %s', $table ),
							);
						}
					}

					// Extract table name (rough).
					if ( preg_match( '/(?:INTO|UPDATE|FROM|TABLE)\s+`?(\w+)`?/i', $q['sql'], $m ) ) {
						$analysis['tables_affected'][] = $m[1];
					}

					break;
				}
			}
		}

		$analysis['tables_affected'] = array_unique( $analysis['tables_affected'] );

		return $analysis;
	}

	/**
	 * Perform combined static + dynamic analysis of a code string.
	 *
	 * Convenience method for the Scanner module.
	 *
	 * @param  string $code    PHP code to analyze.
	 * @param  array  $options Options passed to execute().
	 * @return array {
	 *     @type array $static   Forbidden function findings.
	 *     @type array $dynamic  Execution results (if enabled).
	 *     @type int   $risk     Calculated risk score (0–100).
	 * }
	 */
	public static function analyze_code( string $code, array $options = array() ): array {

		$result = array(
			'static'  => array(),
			'dynamic' => null,
			'risk'    => 0,
		);

		// ── Static analysis ────────────────────────────────────────
		$result['static'] = self::detect_forbidden_calls( $code );

		// Calculate base risk from static findings.
		$risk = 0;

		$category_weights = array(
			'code_execution'         => 25,
			'file_system'            => 15,
			'network'                => 15,
			'wordpress_auth'         => 30,
			'database_direct'        => 20,
			'dangerous_php'          => 20,
			'information_disclosure' => 5,
		);

		foreach ( $result['static'] as $category => $functions ) {
			$weight = $category_weights[ $category ] ?? 10;
			$risk  += $weight * count( $functions );
		}

		// ── Dynamic analysis (optional) ────────────────────────────
		$settings = self::get_settings();

		if ( ! empty( $settings['sandbox_dynamic_analysis'] ) && empty( $options['static_only'] ) ) {

			$exec_options = wp_parse_args(
				$options,
				array(
					'timeout' => 3,
					'preview' => true,
					'label'   => 'Code analysis',
				)
			);

			$result['dynamic'] = self::execute( $code, $exec_options );

			// Increase risk based on dynamic results.
			if ( ! empty( $result['dynamic']['queries'] ) ) {
				$qa = $result['dynamic']['query_analysis'] ?? array();

				$risk += ( $qa['write_queries'] ?? 0 ) * 10;
				$risk += count( $qa['dangerous_queries'] ?? array() ) * 25;
			}

			if ( ! empty( $result['dynamic']['errors'] ) ) {
				// Errors in sandboxed code are suspicious but not
				// necessarily dangerous — slight risk increase.
				$risk += count( $result['dynamic']['errors'] ) * 2;
			}
		}

		$result['risk'] = min( 100, max( 0, $risk ) );

		return $result;
	}

	/*
	================================================================
	 *  7. AJAX — SANDBOX CONSOLE
	 * ============================================================= */

	/**
	 * AJAX handler for the admin Sandbox Console.
	 *
	 * Allows administrators to execute arbitrary PHP in the sandbox
	 * and inspect the results.
	 *
	 * @return void  Sends JSON and dies.
	 */
	public static function ajax_sandbox_console(): void {

		// ── Security checks ────────────────────────────────────────
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Insufficient permissions.' ), 403 );
		}

		check_ajax_referer( 'nexifymy_sandbox_console_nonce', 'nonce' );

		$settings = self::get_settings();
		if ( empty( $settings['sandbox_enabled'] ) ) {
			wp_send_json_error( array( 'message' => 'Sandbox module is disabled.' ), 403 );
		}
		if ( empty( $settings['sandbox_console_enabled'] ) ) {
			wp_send_json_error( array( 'message' => 'Sandbox console is disabled.' ), 403 );
		}

		// ── Read input ─────────────────────────────────────────────
		$code = isset( $_POST['code'] )
			? wp_unslash( $_POST['code'] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			: '';

		// We intentionally do NOT sanitize the code — it's meant to be
		// arbitrary PHP.  The sandbox provides the safety layer.

		if ( empty( trim( $code ) ) ) {
			wp_send_json_error( array( 'message' => 'No code provided.' ), 400 );
		}

		$default_timeout = absint( $settings['sandbox_timeout'] ?? self::DEFAULT_TIMEOUT );
		$timeout         = isset( $_POST['timeout'] ) ? absint( $_POST['timeout'] ) : $default_timeout;
		$timeout         = max( 1, min( 15, $timeout ) ); // clamp 1–15 for console

		// ── Execute in sandbox ─────────────────────────────────────
		$result = self::execute(
			$code,
			array(
				'timeout' => $timeout,
				'preview' => true, // Always rollback in console mode.
				'label'   => 'Admin Sandbox Console',
			)
		);

		self::log(
			'sandbox_console_used',
			sprintf(
				'Admin %s used Sandbox Console (status: %s)',
				wp_get_current_user()->user_login,
				$result['status']
			),
			'info',
			array(
				'user'           => wp_get_current_user()->user_login,
				'code_length'    => strlen( $code ),
				'status'         => $result['status'],
				'execution_time' => $result['execution_time'],
			)
		);

		wp_send_json_success( $result );
	}

	/*
	================================================================
	 *  8. ERROR & SHUTDOWN HANDLERS (Shadow Process)
	 * ============================================================= */

	/**
	 * Custom error handler for the shadow process.
	 *
	 * Captures warnings, notices, and deprecated errors without
	 * halting execution.
	 *
	 * @param  int    $errno   Error level.
	 * @param  string $errstr  Error message.
	 * @param  string $errfile File where the error occurred.
	 * @param  int    $errline Line number.
	 * @return bool            True to suppress the standard PHP handler.
	 */
	public static function shadow_error_handler( int $errno, string $errstr, string $errfile = '', int $errline = 0 ): bool {

		$error_types = array(
			E_WARNING         => 'Warning',
			E_NOTICE          => 'Notice',
			E_DEPRECATED      => 'Deprecated',
			E_USER_WARNING    => 'User Warning',
			E_USER_NOTICE     => 'User Notice',
			E_USER_DEPRECATED => 'User Deprecated',
			E_STRICT          => 'Strict',
		);

		self::$captured_errors[] = array(
			'type'    => $error_types[ $errno ] ?? 'Error (' . $errno . ')',
			'message' => $errstr,
			'file'    => basename( $errfile ),
			'line'    => $errline,
		);

		return true; // Suppress default handler.
	}

	/**
	 * Shutdown handler for the shadow process.
	 *
	 * Catches fatal errors that bypass the regular error handler.
	 * Ensures a JSON response is always sent, even on fatal crash.
	 *
	 * @param  string $payload_id The payload ID for logging.
	 * @return void
	 */
	public static function shadow_shutdown_handler( string $payload_id ): void {

		if ( ! self::$is_shadow ) {
			return; // Only act in shadow processes.
		}

		$error = error_get_last();

		if ( $error === null ) {
			return; // Clean shutdown — response was already sent.
		}

		$fatal_types = array( E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR );

		if ( ! in_array( $error['type'], $fatal_types, true ) ) {
			return; // Not a fatal error.
		}

		// Attempt to rollback DB changes.
		self::rollback_db_savepoint();

		// Clean any partial output buffers.
		while ( ob_get_level() > 0 ) {
			ob_end_clean();
		}

		$result = array(
			'_sentinel_shadow' => true,
			'success'          => false,
			'output'           => '',
			'return_value'     => null,
			'errors'           => array_merge(
				self::$captured_errors,
				array(
					array(
						'type'    => 'Fatal',
						'message' => $error['message'],
						'file'    => basename( $error['file'] ),
						'line'    => $error['line'],
					),
				)
			),
			'queries'          => array(),
			'execution_time'   => 0,
			'memory_peak'      => memory_get_peak_usage( true ),
			'status'           => 'fatal',
		);

		self::log(
			'sandbox_fatal_in_shadow',
			sprintf( 'Fatal error in shadow process: %s', $error['message'] ),
			'critical',
			array(
				'payload_id' => $payload_id,
				'error'      => $error,
			)
		);

		// Send the JSON response manually.
		if ( ! headers_sent() ) {
			header( 'Content-Type: application/json; charset=UTF-8' );
			http_response_code( 200 ); // 200 so the parent can parse our JSON.
		}

		echo wp_json_encode( $result );
		exit;
	}

	/*
	================================================================
	 *  9. SHADOW PROCESS RESPONSE HELPERS
	 * ============================================================= */

	/**
	 * Send a JSON response from the shadow process and terminate.
	 *
	 * @param  array $data    Response data.
	 * @param  int   $status  HTTP status code.
	 * @return never
	 */
	private static function shadow_respond( array $data, int $status = 200 ): void {

		// Ensure the marker is present.
		$data['_sentinel_shadow'] = true;

		if ( ! headers_sent() ) {
			http_response_code( $status );
			header( 'Content-Type: application/json; charset=UTF-8' );
			header( 'Cache-Control: no-store, no-cache' );
			header( 'X-NexifyMy-Shadow: complete' );
		}

		echo wp_json_encode( $data );

		// Use fastcgi_finish_request if available for faster cleanup.
		if ( function_exists( 'fastcgi_finish_request' ) ) {
			fastcgi_finish_request();
		}

		exit;
	}

	/**
	 * Send an error response from the shadow process and terminate.
	 *
	 * @param  string $message Error message.
	 * @param  int    $status  HTTP status code.
	 * @return never
	 */
	private static function shadow_die( string $message, int $status = 403 ): void {

		self::shadow_respond(
			array(
				'_sentinel_shadow' => true,
				'success'          => false,
				'status'           => 'auth_error',
				'errors'           => array(
					array(
						'type'    => 'auth',
						'message' => $message,
					),
				),
			),
			$status
		);
	}

	/*
	================================================================
	 *  10. DOCKER ISOLATION
	 * ============================================================= */

	/**
	 * Detect whether Docker is available on this server.
	 *
	 * Checks for the docker binary and verifies the daemon is running.
	 * Result is cached for the duration of the request.
	 *
	 * @return bool True if Docker is available and the daemon is running.
	 */
	public static function detect_docker_availability(): bool {

		if ( null !== self::$docker_available ) {
			return self::$docker_available;
		}

		// Check if docker binary exists.
		$docker_path = self::find_docker_binary();

		if ( empty( $docker_path ) ) {
			self::$docker_available = false;
			return false;
		}

		// Check if Docker daemon is running.
		$output      = array();
		$return_code = 1;

        // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec
		@exec( 'docker info --format "{{.ServerVersion}}" 2>&1', $output, $return_code );

		self::$docker_available = ( 0 === $return_code );

		self::log(
			'sandbox_docker_detection',
			sprintf(
				'Docker availability: %s (path: %s)',
				self::$docker_available ? 'available' : 'not available',
				$docker_path
			),
			'info',
			array(
				'docker_path'    => $docker_path,
				'daemon_running' => self::$docker_available,
				'server_version' => ! empty( $output[0] ) ? $output[0] : 'unknown',
			)
		);

		return self::$docker_available;
	}

	/**
	 * Locate the Docker binary on this server.
	 *
	 * Handles both Windows and Unix/macOS environments.
	 *
	 * @return string Full path to docker binary, or empty string if not found.
	 */
	private static function find_docker_binary(): string {

		$is_windows = ( strtoupper( substr( PHP_OS, 0, 3 ) ) === 'WIN' );
		$output     = array();

		if ( $is_windows ) {
            // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec
			@exec( 'where docker 2>nul', $output );
		} else {
            // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec
			@exec( 'which docker 2>/dev/null', $output );
		}

		return ! empty( $output[0] ) ? trim( $output[0] ) : '';
	}

	/**
	 * Execute code inside an ephemeral Docker container.
	 *
	 * Creates a temporary PHP harness file, mounts it read-only into a
	 * minimal PHP container with no network access, captures the JSON
	 * output, and cleans up.
	 *
	 * NOTE: Docker containers run raw PHP without WordPress loaded.
	 * For WordPress-aware execution, the self-request method is used
	 * as a fallback.
	 *
	 * @param  string $code    PHP code to execute (without <?php tags).
	 * @param  array  $context Variables to inject into execution scope.
	 * @param  int    $timeout Timeout in seconds.
	 * @param  bool   $preview Whether to rollback DB changes (N/A in Docker).
	 * @return array           Shadow result envelope with 'isolation' => 'docker'.
	 */
	private static function execute_in_docker( string $code, array $context, int $timeout, bool $preview ): array {

		$result = array(
			'_sentinel_shadow' => true,
			'success'          => false,
			'output'           => '',
			'return_value'     => null,
			'errors'           => array(),
			'queries'          => array(),
			'execution_time'   => 0.0,
			'memory_peak'      => 0,
			'status'           => 'pending',
			'isolation'        => 'docker',
		);

		// Build the PHP harness that wraps the user code.
		$harness = self::build_docker_harness( $code, $context );

		// Write harness to a temp file.
		$temp_file = tempnam( sys_get_temp_dir(), 'nexifymy_sbx_' );

		if ( false === $temp_file ) {
			$result['status']   = 'fatal';
			$result['errors'][] = array(
				'type'    => 'system',
				'message' => 'Failed to create temporary file for Docker harness.',
			);
			return $result;
		}

		$harness_path = $temp_file . '.php';

        // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename
		rename( $temp_file, $harness_path );

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === file_put_contents( $harness_path, $harness ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			@unlink( $harness_path );
			$result['status']   = 'fatal';
			$result['errors'][] = array(
				'type'    => 'system',
				'message' => 'Failed to write Docker harness file.',
			);
			return $result;
		}

		// Resolve Docker image from settings or use default.
		$settings     = self::get_settings();
		$docker_image = ! empty( $settings['sandbox_docker_image'] )
			? sanitize_text_field( $settings['sandbox_docker_image'] )
			: self::DOCKER_IMAGE;

		// Docker on Windows needs forward slashes for volume mounts.
		$mount_path = str_replace( '\\', '/', $harness_path );

		$docker_timeout = max( 2, min( 30, $timeout ) );

		// Build the docker run command.
		$cmd = sprintf(
			'docker run --rm --network=none --memory=%s --cpus=%s ' .
			'-v %s:/sandbox/execute.php:ro ' .
			'--read-only --tmpfs /tmp:size=10m ' .
			'--stop-timeout %d ' .
			'%s php -d max_execution_time=%d /sandbox/execute.php 2>&1',
			escapeshellarg( self::DOCKER_MEMORY_LIMIT ),
			escapeshellarg( (string) self::DOCKER_CPU_LIMIT ),
			escapeshellarg( $mount_path ),
			$docker_timeout,
			escapeshellarg( $docker_image ),
			$docker_timeout
		);

		self::log(
			'sandbox_docker_start',
			sprintf( 'Starting Docker execution (image: %s, timeout: %ds)', $docker_image, $docker_timeout ),
			'info',
			array(
				'image'   => $docker_image,
				'timeout' => $docker_timeout,
			)
		);

		$start_time  = microtime( true );
		$output      = array();
		$return_code = 1;

        // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec
		@exec( $cmd, $output, $return_code );

		$elapsed = microtime( true ) - $start_time;

		// Clean up temp file immediately.
        // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
		@unlink( $harness_path );

		// Parse output.
		$raw_output  = implode( "\n", $output );
		$json_result = json_decode( $raw_output, true );

		if ( is_array( $json_result ) && ! empty( $json_result['_sentinel_shadow'] ) ) {
			// Successfully parsed the JSON envelope from the container.
			$result['success']        = ! empty( $json_result['success'] );
			$result['output']         = isset( $json_result['output'] ) ? $json_result['output'] : '';
			$result['return_value']   = $json_result['return_value'] ?? null;
			$result['errors']         = array_merge( $result['errors'], $json_result['errors'] ?? array() );
			$result['execution_time'] = $json_result['execution_time'] ?? round( $elapsed, 4 );
			$result['memory_peak']    = $json_result['memory_peak'] ?? 0;
			$result['status']         = $json_result['status'] ?? 'completed';
		} else {
			// Container returned non-JSON output (fatal error, crash, etc.).
			$result['output']         = substr( $raw_output, 0, self::MAX_OUTPUT_LENGTH );
			$result['execution_time'] = round( $elapsed, 4 );

			if ( 137 === $return_code ) {
				// Exit code 137 = SIGKILL (OOM killer or timeout).
				$result['status']   = 'timeout';
				$result['errors'][] = array(
					'type'    => 'timeout',
					'message' => 'Docker container killed (OOM or timeout).',
				);
			} elseif ( 0 !== $return_code ) {
				$result['status']   = 'fatal';
				$result['errors'][] = array(
					'type'    => 'docker',
					'message' => sprintf( 'Docker container exited with code %d.', $return_code ),
				);
			} else {
				// Exit 0 but no JSON — treat output as raw stdout.
				$result['success'] = true;
				$result['status']  = 'completed';
			}
		}

		return $result;
	}

	/**
	 * Build the PHP harness script for Docker execution.
	 *
	 * Creates a self-contained PHP file that:
	 *   1. Sets up error handling.
	 *   2. Injects context variables.
	 *   3. Executes the user code via eval().
	 *   4. Captures output, errors, and timing.
	 *   5. Outputs a JSON envelope to stdout.
	 *
	 * @param  string $code    PHP code to execute.
	 * @param  array  $context Variables to inject.
	 * @return string          Complete PHP file contents.
	 */
	private static function build_docker_harness( string $code, array $context ): string {

		// Encode context for safe transport into the harness.
		$encoded_context = base64_encode( wp_json_encode( $context ) );
		$escaped_code    = var_export( $code, true );

		$h  = "<?php\n";
		$h .= "// SecureWP360 - Docker Sandbox Harness\n";
		$h .= "// Auto-generated ephemeral file\n\n";

		// Error handler.
		$h .= "error_reporting( E_ALL );\n";
		$h .= "\$_sbx_errors = [];\n";
		$h .= "set_error_handler( function( \$errno, \$errstr, \$errfile, \$errline ) {\n";
		$h .= "    global \$_sbx_errors;\n";
		$h .= "    \$types = [\n";
		$h .= "        E_WARNING => 'Warning', E_NOTICE => 'Notice',\n";
		$h .= "        E_DEPRECATED => 'Deprecated', E_USER_WARNING => 'User Warning',\n";
		$h .= "        E_USER_NOTICE => 'User Notice',\n";
		$h .= "    ];\n";
		$h .= "    \$_sbx_errors[] = [\n";
		$h .= "        'type'    => \$types[ \$errno ] ?? 'Error (' . \$errno . ')',\n";
		$h .= "        'message' => \$errstr,\n";
		$h .= "        'file'    => basename( \$errfile ),\n";
		$h .= "        'line'    => \$errline,\n";
		$h .= "    ];\n";
		$h .= "    return true;\n";
		$h .= "} );\n\n";

		// Inject context variables.
		$h .= "\$_sbx_ctx = json_decode( base64_decode( '" . $encoded_context . "' ), true );\n";
		$h .= "if ( is_array( \$_sbx_ctx ) ) {\n";
		$h .= "    extract( \$_sbx_ctx, EXTR_PREFIX_ALL, 'ctx' );\n";
		$h .= "}\n";
		$h .= "unset( \$_sbx_ctx );\n\n";

		// Execute with output buffering.
		$h .= "\$_sbx_start  = microtime( true );\n";
		$h .= "\$_sbx_return = null;\n";
		$h .= "\$_sbx_status = 'completed';\n";
		$h .= "ob_start();\n\n";

		$h .= "try {\n";
		$h .= '    $_sbx_return = eval( ' . $escaped_code . " );\n";
		$h .= "} catch ( \\Throwable \$e ) {\n";
		$h .= "    \$_sbx_status = 'exception';\n";
		$h .= "    \$_sbx_errors[] = [\n";
		$h .= "        'type'    => get_class( \$e ),\n";
		$h .= "        'message' => \$e->getMessage(),\n";
		$h .= "        'file'    => basename( \$e->getFile() ),\n";
		$h .= "        'line'    => \$e->getLine(),\n";
		$h .= "    ];\n";
		$h .= "}\n\n";

		// Capture output.
		$h .= "\$_sbx_output = ob_get_clean();\n";
		$h .= "if ( false === \$_sbx_output ) {\n";
		$h .= "    \$_sbx_output = '';\n";
		$h .= "}\n\n";

		// Build and emit JSON envelope.
		$h .= "echo json_encode( [\n";
		$h .= "    '_sentinel_shadow' => true,\n";
		$h .= "    'success'          => ( 'completed' === \$_sbx_status ),\n";
		$h .= "    'output'           => substr( \$_sbx_output, 0, 131072 ),\n";
		$h .= "    'return_value'     => \$_sbx_return,\n";
		$h .= "    'errors'           => \$_sbx_errors,\n";
		$h .= "    'queries'          => [],\n";
		$h .= "    'execution_time'   => round( microtime( true ) - \$_sbx_start, 6 ),\n";
		$h .= "    'memory_peak'      => memory_get_peak_usage( true ),\n";
		$h .= "    'status'           => \$_sbx_status,\n";
		$h .= "] );\n";

		return $h;
	}

	/*
	================================================================
	 *  11. UTILITY METHODS
	 * ============================================================= */

	/**
	 * Strip PHP comments from code (reduces false positives in static analysis).
	 *
	 * @param  string $code PHP code.
	 * @return string       Code without comments.
	 */
	private static function strip_php_comments( string $code ): string {

		// Use PHP's tokenizer if available.
		if ( function_exists( 'token_get_all' ) ) {
			$stripped = '';
            $tokens   = @token_get_all( '<?php ' . $code ); // phpcs:ignore

			foreach ( $tokens as $token ) {
				if ( is_array( $token ) ) {
					$type = $token[0];
					if ( $type === T_COMMENT || $type === T_DOC_COMMENT ) {
						$stripped .= str_repeat( "\n", substr_count( $token[1], "\n" ) );
						continue;
					}
					$stripped .= $token[1];
				} else {
					$stripped .= $token;
				}
			}

			// Remove the prepended <?php.
			$stripped = preg_replace( '/^<\?php\s/', '', $stripped );

			return $stripped;
		}

		// Fallback: regex-based (less accurate).
		$code = preg_replace( '#/\*.*?\*/#s', '', $code );  // Block comments.
		$code = preg_replace( '#//[^\n]*#', '', $code );     // Line comments.
		$code = preg_replace( '/#[^\n]*/', '', $code );      // Hash comments.

		return $code;
	}

	/**
	 * Sanitize a return value from eval'd code for JSON encoding.
	 *
	 * @param  mixed $value The value returned by eval.
	 * @return mixed        JSON-safe value.
	 */
	private static function sanitize_return_value( $value ) {

		if ( is_null( $value ) || is_scalar( $value ) ) {
			return $value;
		}

		if ( is_array( $value ) ) {
			return array_map( array( __CLASS__, 'sanitize_return_value' ), $value );
		}

		if ( is_object( $value ) ) {
			return sprintf( '[Object: %s]', get_class( $value ) );
		}

		if ( is_resource( $value ) ) {
			return '[Resource]';
		}

		return '[Unknown type]';
	}

	/**
	 * Read an HTTP header from the current request.
	 *
	 * @param  string $name Header name (e.g., 'X-My-Header').
	 * @return string       Header value or empty string.
	 */
	private static function get_request_header( string $name ): string {

		// WordPress / Apache style.
		$server_key = 'HTTP_' . strtoupper( str_replace( '-', '_', $name ) );

		if ( ! empty( $_SERVER[ $server_key ] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER[ $server_key ] ) );
		}

		// Try getallheaders() for Nginx with FastCGI.
		if ( function_exists( 'getallheaders' ) ) {
			$headers = getallheaders();
			if ( is_array( $headers ) ) {
				foreach ( $headers as $key => $value ) {
					if ( strcasecmp( $key, $name ) === 0 ) {
						return sanitize_text_field( $value );
					}
				}
			}
		}

		return '';
	}

	/**
	 * Get the client's IP address.
	 *
	 * @return string
	 */
	private static function get_client_ip(): string {
		$remote_addr     = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		if ( $remote_addr && in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			$headers = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP' );

			foreach ( $headers as $header ) {
				if ( empty( $_SERVER[ $header ] ) ) {
					continue;
				}

				$raw = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
				$ip  = trim( strtok( $raw, ',' ) );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		if ( $remote_addr && filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
			return $remote_addr;
		}

		return '0.0.0.0';
	}

	/**
	 * Get this server's own IP address.
	 *
	 * @return string
	 */
	private static function get_server_ip(): string {

		if ( ! empty( $_SERVER['SERVER_ADDR'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) );
		}

		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		$ip   = gethostbyname( $host );

		return ( $ip !== $host ) ? $ip : '127.0.0.1';
	}

	/**
	 * Retrieve cached module settings.
	 *
	 * @return array
	 */
	public static function get_settings(): array {

		if ( self::$settings_cache !== null ) {
			return self::$settings_cache;
		}

		$defaults = array(
			'sandbox_enabled'          => false,  // Opt-in.
			'sandbox_timeout'          => self::DEFAULT_TIMEOUT,
			'sandbox_dynamic_analysis' => false,  // Static-only by default.
			'sandbox_console_enabled'  => false,  // Admin console off by default.
			'sandbox_prefer_docker'    => false,  // Use Docker isolation when available.
			'sandbox_docker_image'     => self::DOCKER_IMAGE,
		);

		$stored = get_option( 'nexifymy_security_settings', array() );

		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		$module_settings = ( isset( $stored['modules'] ) && is_array( $stored['modules'] ) ) ? $stored['modules'] : array();
		foreach ( array_keys( $defaults ) as $key ) {
			if ( array_key_exists( $key, $module_settings ) ) {
				$stored[ $key ] = $module_settings[ $key ];
			}
		}

		self::$settings_cache = wp_parse_args( $stored, $defaults );

		return self::$settings_cache;
	}

	/**
	 * Flush settings cache.
	 *
	 * @return void
	 */
	public static function flush_settings_cache(): void {
		self::$settings_cache = null;
	}

	/**
	 * Log wrapper.
	 *
	 * @param  string $type    Event type.
	 * @param  string $message Description.
	 * @param  string $level   Severity.
	 * @param  array  $data    Context.
	 * @return void
	 */
	private static function log( string $type, string $message, string $level = 'info', array $data = array() ): void {

		if ( class_exists( 'NexifyMy_Security_Logger' ) && method_exists( 'NexifyMy_Security_Logger', 'log' ) ) {
			NexifyMy_Security_Logger::log( $type, $message, $level, $data );
			return;
		}

        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		error_log(
			sprintf(
				'[SentinelWP Sandbox] [%s] [%s] %s | %s',
				strtoupper( $level ),
				$type,
				$message,
				wp_json_encode( $data )
			)
		);
	}

	/**
	 * Reset state for unit tests.
	 *
	 * @internal
	 * @return void
	 */
	public static function _reset(): void {
		self::$initialised      = false;
		self::$settings_cache   = null;
		self::$captured_errors  = array();
		self::$is_shadow        = false;
		self::$docker_available = null;
	}
}
