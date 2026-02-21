<?php
/**
 * P2P (Peer-to-Peer) Threat Intelligence Module
 *
 * Creates a collaborative defence network between SentinelWP installations:
 *   1. Threat Sharing  — broadcasts blocked IPs/hashes to registered peers.
 *   2. Threat Reception — REST endpoint receives intelligence from peers.
 *   3. Trust Scoring    — only auto-blocks when confidence exceeds threshold.
 *   4. Cron Sync        — hourly heartbeat keeps peer status current.
 *
 * @package NexifyMy_Security
 */

// ── Prevent direct access ──────────────────────────────────────────────
if ( ! defined( 'ABSPATH' ) ) {
	exit( 'Direct access denied.' );
}

/**
 * Class NexifyMy_Security_P2P
 *
 * Singleton-style static module matching the existing SentinelWP pattern.
 */
class NexifyMy_Security_P2P {

	/*
	================================================================
	 *  Constants
	 * ============================================================= */

	/** REST API namespace. */
	const REST_NAMESPACE = 'nexifymy/v1';

	/** REST route path for receiving threat intelligence. */
	const REST_ROUTE_RECEIVE = '/p2p/receive';

	/** REST route path for peer handshake / heartbeat. */
	const REST_ROUTE_HEARTBEAT = '/p2p/heartbeat';

	/** REST route path for earning credits. */
	const REST_ROUTE_EARN_CREDITS = '/p2p/earn-credits';

	/** REST route path for retrieving credits/reputation. */
	const REST_ROUTE_MY_CREDITS = '/p2p/my-credits';

	/** REST route path for redeeming benefits. */
	const REST_ROUTE_REDEEM = '/p2p/redeem';

	/** Cron hook name for periodic sync. */
	const CRON_HOOK = 'nexifymy_p2p_sync';

	/** Option key for storing the list of registered peers. */
	const PEERS_OPTION = 'nexifymy_p2p_peers';

	/** Option key for the local node's unique API key. */
	const NODE_KEY_OPTION = 'nexifymy_p2p_node_key';

	/** Transient prefix for caching received threat IPs. */
	const TRANSIENT_PREFIX = 'nexifymy_p2p_block_';

	/** Transient prefix for rate-limiting inbound requests per peer. */
	const RATE_LIMIT_PREFIX = 'nexifymy_p2p_rl_';

	/** Maximum number of threats accepted per peer per minute. */
	const RATE_LIMIT_MAX = 30;

	/** Default trust threshold (0–100). Only threats ≥ this score are auto-blocked. */
	const DEFAULT_TRUST_THRESHOLD = 70;

	/** TTL for cached threat transients (seconds). */
	const THREAT_CACHE_TTL = 86400; // 24 hours

	/** HTTP timeout for outbound peer requests (seconds). */
	const HTTP_TIMEOUT = 10;

	/** Maximum number of peers allowed. */
	const MAX_PEERS = 50;

	/** Option key for credit table schema version. */
	const CREDITS_SCHEMA_OPTION = 'nexifymy_p2p_credits_schema_version';

	/** Current credit table schema version. */
	const CREDITS_SCHEMA_VERSION = '1.0.0';

	/** Credits table suffix. */
	const CREDITS_TABLE = 'nexifymy_p2p_credits';

	/** Option key for cached credit data by site_id hash. */
	const CREDITS_CACHE_OPTION = 'nexifymy_p2p_credits_cache';

	/** Option key for cached accuracy percentages by site_id hash. */
	const CREDITS_ACCURACY_OPTION = 'nexifymy_p2p_credits_accuracy';

	/** Option key for contribution counters by site_id hash. */
	const CREDITS_CONTRIBUTION_OPTION = 'nexifymy_p2p_contribution_counts';

	/** Option key for redeemed benefits per site hash. */
	const CREDITS_BENEFITS_OPTION = 'nexifymy_p2p_redeemed_benefits';

	/** Transient prefix for threat validation votes. */
	const VALIDATION_PREFIX = 'nexifymy_p2p_validation_';

	/*
	================================================================
	 *  Properties
	 * ============================================================= */

	/** @var bool Prevents double-initialisation. */
	private static $initialised = false;

	/** @var array|null Cached module settings. */
	private static $settings_cache = null;

	/*
	================================================================
	 *  1. INITIALISATION
	 * ============================================================= */

	/**
	 * Bootstrap the P2P module.
	 *
	 * Called from the main plugin loader after Firewall and Logger are
	 * available.  Registers all hooks, REST routes, and the cron job.
	 *
	 * @return void
	 */
	public static function init() {

		if ( self::$initialised ) {
			return;
		}
		self::$initialised = true;

		$settings = self::get_settings();

		if ( empty( $settings['p2p_enabled'] ) ) {
			return; // Module disabled.
		}

		// Ensure this node has a unique API key.
		self::ensure_node_key();

		// Ensure credit/reputation schema exists.
		self::maybe_create_credits_table();

		/*
		 * Hook into the action fired by WAF / Deception / Login modules
		 * when they block an IP.  This is the outbound broadcast trigger.
		 *
		 * Expected signature:
		 *   do_action( 'nexifymy_threat_detected', $ip, $reason, $score );
		 */
		add_action( 'nexifymy_threat_detected', array( __CLASS__, 'on_threat_detected' ), 10, 3 );

		/*
		 * Register REST API endpoints for inbound communication.
		 */
		add_action( 'rest_api_init', array( __CLASS__, 'register_rest_routes' ) );

		/*
		 * Schedule the hourly sync cron if not already scheduled.
		 */
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'hourly', self::CRON_HOOK );
		}
		add_action( self::CRON_HOOK, array( __CLASS__, 'cron_sync' ) );

		/*
		 * Clean up cron on plugin deactivation (hooked elsewhere, but
		 * we also listen here for a dedicated deactivation action).
		 */
		add_action( 'nexifymy_security_deactivate', array( __CLASS__, 'deactivate' ) );
	}

	/**
	 * Clean-up on plugin deactivation.
	 *
	 * @return void
	 */
	public static function deactivate() {
		$timestamp = wp_next_scheduled( self::CRON_HOOK );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, self::CRON_HOOK );
		}
	}

	/*
	================================================================
	 *  2. PEER MANAGEMENT
	 * ============================================================= */

	/**
	 * Return the list of registered peers.
	 *
	 * Each peer is an associative array:
	 *   [
	 *     'url'           => 'https://example.com',
	 *     'api_key'       => 'their-node-key',
	 *     'label'         => 'My other site',
	 *     'added_at'      => '2025-01-15 10:30:00',
	 *     'last_sync'     => '2025-01-15 12:00:00',  // updated by cron
	 *     'last_status'   => 'ok' | 'error' | 'unknown',
	 *     'threats_sent'  => 42,
	 *     'threats_recv'  => 18,
	 *   ]
	 *
	 * @return array  Indexed array of peer arrays.
	 */
	public static function get_peers() {

		$peers = get_option( self::PEERS_OPTION, array() );

		if ( ! is_array( $peers ) ) {
			return array();
		}

		return $peers;
	}

	/**
	 * Add or update a peer in the registry.
	 *
	 * @param  string $url     The peer's site URL (must be HTTPS in production).
	 * @param  string $api_key The peer's node key for authentication.
	 * @param  string $label   Human-readable label (optional).
	 * @return array|WP_Error  The peer record on success, WP_Error on failure.
	 */
	public static function register_peer( $url, $api_key, $label = '' ) {

		// ── Validate URL ───────────────────────────────────────────
		$url = esc_url_raw( untrailingslashit( trim( $url ) ) );

		if ( empty( $url ) || ! filter_var( $url, FILTER_VALIDATE_URL ) ) {
			return new WP_Error( 'invalid_url', __( 'The peer URL is not valid.', 'nexifymy-security' ) );
		}

		// Prevent adding self.
		if ( untrailingslashit( home_url() ) === $url ) {
			return new WP_Error( 'self_peer', __( 'You cannot add your own site as a peer.', 'nexifymy-security' ) );
		}

		// ── Validate API key ──────────────────────────────────────
		$api_key = sanitize_text_field( trim( $api_key ) );

		if ( strlen( $api_key ) < 16 ) {
			return new WP_Error( 'invalid_key', __( 'API key must be at least 16 characters.', 'nexifymy-security' ) );
		}

		// ── Check limits ──────────────────────────────────────────
		$peers = self::get_peers();

		if ( count( $peers ) >= self::MAX_PEERS ) {
			return new WP_Error(
				'max_peers',
				sprintf(
					__( 'Maximum number of peers (%d) reached.', 'nexifymy-security' ),
					self::MAX_PEERS
				)
			);
		}

		// ── Check for duplicate ───────────────────────────────────
		foreach ( $peers as $key => $existing ) {
			if ( untrailingslashit( $existing['url'] ) === $url ) {
				// Update existing peer.
				$peers[ $key ]['api_key'] = $api_key;
				$peers[ $key ]['label']   = sanitize_text_field( $label );
				update_option( self::PEERS_OPTION, $peers );

				self::log(
					'p2p_peer_updated',
					sprintf( 'Peer updated: %s', $url ),
					'info',
					$peers[ $key ]
				);

				return $peers[ $key ];
			}
		}

		// ── Create new peer record ────────────────────────────────
		$peer = array(
			'id'           => wp_generate_uuid4(),
			'url'          => $url,
			'api_key'      => $api_key,
			'label'        => sanitize_text_field( $label ),
			'added_at'     => current_time( 'mysql' ),
			'last_sync'    => null,
			'last_status'  => 'unknown',
			'threats_sent' => 0,
			'threats_recv' => 0,
		);

		$peers[] = $peer;
		update_option( self::PEERS_OPTION, $peers );

		self::log(
			'p2p_peer_registered',
			sprintf( 'New peer registered: %s', $url ),
			'info',
			$peer
		);

		return $peer;
	}

	/**
	 * Remove a peer by its ID or URL.
	 *
	 * @param  string $identifier  The peer's UUID or URL.
	 * @return bool                True if removed, false if not found.
	 */
	public static function remove_peer( $identifier ) {

		$peers   = self::get_peers();
		$found   = false;
		$updated = array();

		foreach ( $peers as $peer ) {
			if ( $peer['id'] === $identifier || untrailingslashit( $peer['url'] ) === untrailingslashit( $identifier ) ) {
				$found = true;
				self::log(
					'p2p_peer_removed',
					sprintf( 'Peer removed: %s (%s)', $peer['url'], $peer['id'] ),
					'info',
					$peer
				);
				continue; // Skip — effectively deletes.
			}
			$updated[] = $peer;
		}

		if ( $found ) {
			update_option( self::PEERS_OPTION, $updated );
		}

		return $found;
	}

	/**
	 * Generate and store a unique node key if one doesn't exist.
	 *
	 * The node key identifies THIS installation to its peers.
	 *
	 * @return string  The node key.
	 */
	public static function ensure_node_key() {

		$key = get_option( self::NODE_KEY_OPTION, '' );

		if ( ! empty( $key ) && is_string( $key ) ) {
			return $key;
		}

		// Generate a cryptographically secure 48-character hex key.
		$key = bin2hex( random_bytes( 24 ) );

		update_option( self::NODE_KEY_OPTION, $key );

		self::log(
			'p2p_node_key_generated',
			'New P2P node key generated.',
			'info'
		);

		return $key;
	}

	/**
	 * Return this node's API key.
	 *
	 * @return string
	 */
	public static function get_node_key() {
		return self::ensure_node_key();
	}

	/*
	================================================================
	 *  3. BROADCAST (OUTBOUND)
	 * ============================================================= */

	/**
	 * Action callback: a threat was detected locally.
	 *
	 * Fired by `do_action( 'nexifymy_threat_detected', $ip, $reason, $score )`.
	 *
	 * @param  string $ip     The blocked IP address.
	 * @param  string $reason Human-readable reason.
	 * @param  int    $score  Confidence score (0–100).
	 * @return void
	 */
	public static function on_threat_detected( $ip, $reason = '', $score = 85 ) {

		$settings = self::get_settings();

		if ( empty( $settings['p2p_broadcast_enabled'] ) ) {
			return;
		}

		// Validate IP.
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}

		// Clamp score.
		$score = max( 0, min( 100, intval( $score ) ) );

		// Fire the broadcast asynchronously if possible.
		// For simplicity we call synchronously here; a production
		// implementation might use Action Scheduler or wp_schedule_single_event().
		self::broadcast_threat( $ip, $reason, $score );
	}

	/**
	 * Broadcast a threat to all registered peers.
	 *
	 * Sends a signed JSON POST to each peer's REST receive endpoint.
	 *
	 * Payload:
	 *   {
	 *     "ip":        "1.2.3.4",
	 *     "reason":    "Honeytrap triggered: /backup.sql",
	 *     "score":     90,
	 *     "timestamp": "2025-01-15T12:34:56+00:00",
	 *     "source":    "https://mysite.com",
	 *     "signature": "hmac-sha256-hex"
	 *   }
	 *
	 * @param  string $ip     IP address to broadcast.
	 * @param  string $reason Description of the threat.
	 * @param  int    $score  Confidence score (0–100).
	 * @return array          Results keyed by peer URL: 'ok' | WP_Error.
	 */
	public static function broadcast_threat( $ip, $reason, $score ) {

		$peers   = self::get_peers();
		$results = array();

		if ( empty( $peers ) ) {
			return $results;
		}

		$node_key  = self::get_node_key();
		$timestamp = gmdate( 'c' ); // ISO 8601 UTC
		$source    = untrailingslashit( home_url() );

		// Build the payload.
		$payload = array(
			'ip'        => sanitize_text_field( $ip ),
			'reason'    => sanitize_text_field( $reason ),
			'score'     => intval( $score ),
			'timestamp' => $timestamp,
			'source'    => $source,
			'type'      => 'ip_block', // future: 'malware_hash', 'url_pattern', etc.
		);

		$success_count = 0;

		foreach ( $peers as $index => $peer ) {

			$endpoint = trailingslashit( $peer['url'] ) . 'wp-json/' . self::REST_NAMESPACE . self::REST_ROUTE_RECEIVE;

			// Create an HMAC signature using the PEER's API key as the shared secret.
			// The receiving peer can verify this matches their own key.
			$signature = self::sign_payload( $payload, $peer['api_key'] );

			$headers = array(
				'Content-Type'         => 'application/json',
				'X-NexifyMy-Node-Key'  => $node_key,
				'X-NexifyMy-Signature' => $signature,
			);

			$response = wp_remote_post(
				$endpoint,
				array(
					'timeout'   => self::HTTP_TIMEOUT,
					'headers'   => $headers,
					'body'      => wp_json_encode( $payload ),
					'sslverify' => true,
					'blocking'  => true,
				)
			);

			if ( is_wp_error( $response ) ) {

				$results[ $peer['url'] ] = $response;

				self::log(
					'p2p_broadcast_failed',
					sprintf(
						'Failed to broadcast threat %s to peer %s: %s',
						$ip,
						$peer['url'],
						$response->get_error_message()
					),
					'warning',
					array(
						'peer'  => $peer['url'],
						'ip'    => $ip,
						'error' => $response->get_error_message(),
					)
				);

				// Update peer status.
				$peers[ $index ]['last_status'] = 'error';

			} else {

				$code = wp_remote_retrieve_response_code( $response );

				if ( $code >= 200 && $code < 300 ) {
					$results[ $peer['url'] ]         = 'ok';
					$peers[ $index ]['threats_sent'] = intval( $peer['threats_sent'] ) + 1;
					$peers[ $index ]['last_status']  = 'ok';
					++$success_count;
				} else {
					$body                           = wp_remote_retrieve_body( $response );
					$results[ $peer['url'] ]        = new WP_Error(
						'peer_http_error',
						sprintf( 'HTTP %d: %s', $code, substr( $body, 0, 200 ) )
					);
					$peers[ $index ]['last_status'] = 'error';

					self::log(
						'p2p_broadcast_error',
						sprintf( 'Peer %s returned HTTP %d for threat %s', $peer['url'], $code, $ip ),
						'warning',
						array(
							'peer'      => $peer['url'],
							'ip'        => $ip,
							'http_code' => $code,
						)
					);
				}
			}
		}

		// Award contribution credits once per successful threat-share event.
		if ( $success_count > 0 ) {
			$site_id = self::get_anonymous_site_id();
			self::award_credits( $site_id, 'blocked_ip', 1 );

			if ( false !== stripos( $reason, 'zero-day' ) || false !== stripos( $reason, 'zeroday' ) ) {
				self::award_credits( $site_id, 'zero_day', 1 );
			}
		}

		// Persist updated peer stats.
		update_option( self::PEERS_OPTION, $peers );

		return $results;
	}

	/*
	================================================================
	 *  4. RECEIVE (INBOUND — REST API)
	 * ============================================================= */

	/**
	 * Register REST API routes for P2P communication.
	 *
	 * Hooked to: `rest_api_init`.
	 *
	 * @return void
	 */
	public static function register_rest_routes() {

		/*
		 * POST /wp-json/nexifymy/v1/p2p/receive
		 *
		 * Accepts threat intelligence from a peer.
		 */
		register_rest_route(
			self::REST_NAMESPACE,
			self::REST_ROUTE_RECEIVE,
			array(
				'methods'             => WP_REST_Server::CREATABLE, // POST
				'callback'            => array( __CLASS__, 'rest_receive_threat' ),
				'permission_callback' => array( __CLASS__, 'rest_permission_check' ),
				'args'                => self::get_receive_endpoint_args(),
			)
		);

		/*
		 * GET /wp-json/nexifymy/v1/p2p/heartbeat
		 *
		 * Lightweight endpoint for cron-based health checks.
		 */
		register_rest_route(
			self::REST_NAMESPACE,
			self::REST_ROUTE_HEARTBEAT,
			array(
				'methods'             => WP_REST_Server::READABLE, // GET
				'callback'            => array( __CLASS__, 'rest_heartbeat' ),
				'permission_callback' => array( __CLASS__, 'rest_permission_check' ),
			)
		);

		/*
		 * POST /wp-json/nexifymy/v1/p2p/earn-credits
		 *
		 * Awards credits for a contribution event.
		 */
		register_rest_route(
			self::REST_NAMESPACE,
			self::REST_ROUTE_EARN_CREDITS,
			array(
				'methods'             => WP_REST_Server::CREATABLE, // POST
				'callback'            => array( __CLASS__, 'rest_earn_credits' ),
				'permission_callback' => array( __CLASS__, 'rest_admin_or_peer_permission' ),
				'args'                => array(
					'site_id'           => array(
						'required'          => false,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					),
					'contribution_type' => array(
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_key',
					),
					'value'             => array(
						'required'          => false,
						'type'              => 'integer',
						'default'           => 1,
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		/*
		 * GET /wp-json/nexifymy/v1/p2p/my-credits
		 *
		 * Returns credit balance, reputation, accuracy and badges.
		 */
		register_rest_route(
			self::REST_NAMESPACE,
			self::REST_ROUTE_MY_CREDITS,
			array(
				'methods'             => WP_REST_Server::READABLE, // GET
				'callback'            => array( __CLASS__, 'rest_my_credits' ),
				'permission_callback' => array( __CLASS__, 'rest_admin_or_peer_permission' ),
				'args'                => array(
					'site_id' => array(
						'required'          => false,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);

		/*
		 * POST /wp-json/nexifymy/v1/p2p/redeem
		 *
		 * Redeems credits for premium benefits.
		 */
		register_rest_route(
			self::REST_NAMESPACE,
			self::REST_ROUTE_REDEEM,
			array(
				'methods'             => WP_REST_Server::CREATABLE, // POST
				'callback'            => array( __CLASS__, 'rest_redeem_credits' ),
				'permission_callback' => array( __CLASS__, 'rest_admin_or_peer_permission' ),
				'args'                => array(
					'site_id'      => array(
						'required'          => false,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					),
					'benefit_type' => array(
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_key',
					),
					'credits'      => array(
						'required'          => false,
						'type'              => 'integer',
						'sanitize_callback' => 'absint',
					),
				),
			)
		);
	}

	/**
	 * Define the accepted arguments for the /receive endpoint.
	 *
	 * @return array
	 */
	private static function get_receive_endpoint_args() {

		return array(
			'ip'        => array(
				'required'          => true,
				'type'              => 'string',
				'description'       => 'The IP address to block.',
				'validate_callback' => function ( $value ) {
					return (bool) filter_var( $value, FILTER_VALIDATE_IP );
				},
				'sanitize_callback' => 'sanitize_text_field',
			),
			'reason'    => array(
				'required'          => false,
				'type'              => 'string',
				'default'           => 'Reported by P2P peer',
				'sanitize_callback' => 'sanitize_text_field',
			),
			'score'     => array(
				'required'          => false,
				'type'              => 'integer',
				'default'           => 50,
				'validate_callback' => function ( $value ) {
					return is_numeric( $value ) && $value >= 0 && $value <= 100;
				},
				'sanitize_callback' => 'absint',
			),
			'timestamp' => array(
				'required'          => false,
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
			),
			'source'    => array(
				'required'          => false,
				'type'              => 'string',
				'sanitize_callback' => 'esc_url_raw',
			),
			'type'      => array(
				'required'          => false,
				'type'              => 'string',
				'default'           => 'ip_block',
				'sanitize_callback' => 'sanitize_key',
			),
		);
	}

	/**
	 * Permission callback for all P2P REST endpoints.
	 *
	 * Validates the request by:
	 *   1. Checking for the X-NexifyMy-Node-Key header.
	 *   2. Verifying the key belongs to a registered peer.
	 *   3. Optionally verifying the HMAC signature.
	 *   4. Enforcing rate limits.
	 *
	 * @param  WP_REST_Request $request The incoming request.
	 * @return bool|WP_Error            True if allowed, WP_Error otherwise.
	 */
	public static function rest_permission_check( WP_REST_Request $request ) {

		// ── 1. Extract the node key header ─────────────────────────
		$remote_node_key = $request->get_header( 'X-NexifyMy-Node-Key' );

		if ( empty( $remote_node_key ) ) {
			return new WP_Error(
				'rest_forbidden',
				__( 'Missing authentication header.', 'nexifymy-security' ),
				array( 'status' => 403 )
			);
		}

		$remote_node_key = sanitize_text_field( $remote_node_key );

		// ── 2. Look up the peer by their node key ──────────────────
		$peers      = self::get_peers();
		$peer_found = false;
		$peer_index = null;

		foreach ( $peers as $index => $peer ) {
			/*
			 * The sender uses OUR api_key (stored on their side) to sign,
			 * and sends THEIR node_key in the header so we know WHO they are.
			 * We look up the peer whose 'api_key' field we have on file
			 * — but since we store THEIR key as 'api_key', we match on
			 * their node key against our stored records.
			 *
			 * Simplified approach: we store the peer's node key AS their api_key.
			 */
			if ( hash_equals( $peer['api_key'], $remote_node_key ) ) {
				$peer_found = true;
				$peer_index = $index;
				break;
			}
		}

		if ( ! $peer_found ) {
			self::log(
				'p2p_auth_failed',
				sprintf( 'P2P authentication failed — unknown node key from %s', self::get_client_ip() ),
				'warning',
				array(
					'ip'         => self::get_client_ip(),
					'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
				)
			);

			return new WP_Error(
				'rest_forbidden',
				__( 'Invalid node key. Peer not recognised.', 'nexifymy-security' ),
				array( 'status' => 403 )
			);
		}

		// ── 3. Verify HMAC signature (if present) ──────────────────
		$signature = $request->get_header( 'X-NexifyMy-Signature' );

		if ( ! empty( $signature ) ) {
			$body    = $request->get_body();
			$payload = json_decode( $body, true );

			if ( is_array( $payload ) ) {
				$my_node_key  = self::get_node_key();
				$expected_sig = self::sign_payload( $payload, $my_node_key );

				if ( ! hash_equals( $expected_sig, $signature ) ) {
					return new WP_Error(
						'rest_forbidden',
						__( 'Invalid request signature.', 'nexifymy-security' ),
						array( 'status' => 403 )
					);
				}
			}
		}

		// ── 4. Rate limiting ───────────────────────────────────────
		$rl_key = self::RATE_LIMIT_PREFIX . md5( $remote_node_key );
		$count  = intval( get_transient( $rl_key ) );

		if ( $count >= self::RATE_LIMIT_MAX ) {
			return new WP_Error(
				'rest_rate_limit',
				__( 'Rate limit exceeded. Try again later.', 'nexifymy-security' ),
				array( 'status' => 429 )
			);
		}

		set_transient( $rl_key, $count + 1, MINUTE_IN_SECONDS );

		// ── Attach peer info to the request for use in the callback.
		$request->set_param( '_nexifymy_peer_index', $peer_index );

		return true;
	}

	/**
	 * Permission callback allowing either authenticated admin users
	 * or authenticated P2P peer requests.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return bool|WP_Error
	 */
	public static function rest_admin_or_peer_permission( WP_REST_Request $request ) {
		if ( function_exists( 'current_user_can' ) && current_user_can( 'manage_options' ) ) {
			return true;
		}

		return self::rest_permission_check( $request );
	}

	/**
	 * REST callback: receive a threat report from a peer.
	 *
	 * @param  WP_REST_Request $request
	 * @return WP_REST_Response|WP_Error
	 */
	public static function rest_receive_threat( WP_REST_Request $request ) {

		$ip        = $request->get_param( 'ip' );
		$reason    = $request->get_param( 'reason' );
		$score     = intval( $request->get_param( 'score' ) );
		$source    = $request->get_param( 'source' );
		$timestamp = $request->get_param( 'timestamp' );
		$type      = $request->get_param( 'type' );

		$peer_index = $request->get_param( '_nexifymy_peer_index' );
		$peers      = self::get_peers();
		$peer_url   = isset( $peers[ $peer_index ] ) ? $peers[ $peer_index ]['url'] : 'unknown';

		// ── Check for duplicate (already received this IP recently) ─
		$cache_key = self::TRANSIENT_PREFIX . md5( $ip );

		if ( false !== get_transient( $cache_key ) ) {
			return new WP_REST_Response(
				array(
					'status'  => 'duplicate',
					'message' => 'This IP was already reported recently.',
				),
				200
			);
		}

		// ── Store in transient cache ───────────────────────────────
		$intel = array(
			'ip'        => $ip,
			'reason'    => $reason,
			'score'     => $score,
			'source'    => $source,
			'peer'      => $peer_url,
			'timestamp' => $timestamp ?: current_time( 'mysql' ),
			'type'      => $type,
			'received'  => current_time( 'mysql' ),
			'action'    => 'none', // will be updated below
		);

		// ── Decide whether to auto-block ───────────────────────────
		$settings  = self::get_settings();
		$threshold = isset( $settings['p2p_trust_threshold'] )
			? intval( $settings['p2p_trust_threshold'] )
			: self::DEFAULT_TRUST_THRESHOLD;

		$blocked        = false;
		$source_site_id = self::get_anonymous_site_id( $source ? $source : $peer_url );

		if ( $score >= $threshold ) {

			// Don't block our own server IP.
			if ( $ip === self::get_server_ip() ) {
				self::log(
					'p2p_self_block_prevented',
					sprintf( 'Prevented self-block of server IP %s from peer %s', $ip, $peer_url ),
					'warning',
					$intel
				);
			} else {
				$blocked = self::block_ip(
					$ip,
					sprintf( 'P2P: %s (score %d, peer %s)', $reason, $score, $peer_url )
				);

				if ( $blocked ) {
					$intel['action'] = 'blocked';
					self::record_validation_vote( $ip, 'block' );
					self::update_accuracy_by_feedback( $source_site_id, true );
					self::award_credits( $source_site_id, 'high_quality_report', 1 );

					self::log(
						'p2p_preemptive_block',
						sprintf(
							'Preemptively blocked IP %s reported by peer %s (score: %d)',
							$ip,
							$peer_url,
							$score
						),
						'critical',
						$intel
					);
				} else {
					$intel['action'] = 'block_failed';
					self::log(
						'p2p_preemptive_block_failed',
						sprintf(
							'Could not block IP %s reported by peer %s (score: %d)',
							$ip,
							$peer_url,
							$score
						),
						'warning',
						$intel
					);
				}
			}
		} else {
			$intel['action'] = 'logged_only';

			self::log(
				'p2p_threat_logged',
				sprintf(
					'Threat received for IP %s from peer %s (score: %d — below threshold %d)',
					$ip,
					$peer_url,
					$score,
					$threshold
				),
				'info',
				$intel
			);
		}

		// If peers propagate allowlist events, treat this as false-positive feedback.
		if ( 'allowlist' === $type || 'false_positive' === $type ) {
			$majority_allowlisted = self::record_validation_vote( $ip, 'allowlist' );
			if ( $majority_allowlisted ) {
				self::update_accuracy_by_feedback( $source_site_id, false );
			}
		}

		// Cache the intelligence regardless of block decision.
		set_transient( $cache_key, $intel, self::THREAT_CACHE_TTL );

		// ── Update peer stats ──────────────────────────────────────
		if ( isset( $peers[ $peer_index ] ) ) {
			$peers[ $peer_index ]['threats_recv'] = intval( $peers[ $peer_index ]['threats_recv'] ) + 1;
			$peers[ $peer_index ]['last_sync']    = current_time( 'mysql' );
			$peers[ $peer_index ]['last_status']  = 'ok';
			update_option( self::PEERS_OPTION, $peers );
		}

		// ── Track 24h counter for admin dashboard ──────────────────
		self::increment_daily_counter();

		return new WP_REST_Response(
			array(
				'status'  => 'accepted',
				'blocked' => $blocked,
				'message' => $blocked
					? 'IP has been preemptively blocked.'
					: 'Threat logged but below trust threshold.',
			),
			200
		);
	}

	/**
	 * REST callback: heartbeat endpoint for peer health checks.
	 *
	 * @param  WP_REST_Request $request
	 * @return WP_REST_Response
	 */
	public static function rest_heartbeat( WP_REST_Request $request ) {

		return new WP_REST_Response(
			array(
				'status'    => 'ok',
				'plugin'    => 'SentinelWP',
				'module'    => 'p2p-intelligence',
				'version'   => '1.0.0',
				'timestamp' => gmdate( 'c' ),
			),
			200
		);
	}

	/*
	================================================================
	 *  5. CREDITS / REPUTATION / REDEEM
	 * ============================================================= */

	/**
	 * Ensure credits table exists.
	 *
	 * @return void
	 */
	public static function maybe_create_credits_table() {
		$current = get_option( self::CREDITS_SCHEMA_OPTION, '' );
		if ( self::CREDITS_SCHEMA_VERSION === $current ) {
			return;
		}

		self::create_credits_table();
	}

	/**
	 * Create credits table schema.
	 *
	 * @return void
	 */
	public static function create_credits_table() {
		global $wpdb;

		if ( empty( $wpdb ) ) {
			return;
		}

		if ( ! function_exists( 'dbDelta' ) ) {
			$upgrade_file = ABSPATH . 'wp-admin/includes/upgrade.php';
			if ( file_exists( $upgrade_file ) ) {
				require_once $upgrade_file;
			}
		}

		if ( ! function_exists( 'dbDelta' ) ) {
			return;
		}

		$table_name      = self::get_credits_table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            site_id varchar(128) NOT NULL,
            credits_earned bigint(20) unsigned NOT NULL DEFAULT 0,
            credits_spent bigint(20) unsigned NOT NULL DEFAULT 0,
            reputation_score decimal(14,2) NOT NULL DEFAULT 0,
            last_contribution datetime NULL,
            PRIMARY KEY (id),
            UNIQUE KEY site_id (site_id)
        ) {$charset_collate};";

		dbDelta( $sql );
		update_option( self::CREDITS_SCHEMA_OPTION, self::CREDITS_SCHEMA_VERSION, false );
	}

	/**
	 * Award credits to a contributor.
	 *
	 * @param string $site_id Contributor site hash.
	 * @param string $contribution_type Contribution category.
	 * @param int    $value Multiplier.
	 * @return array|WP_Error
	 */
	public static function award_credits( $site_id, $contribution_type, $value = 1 ) {
		$site_id = self::normalize_site_id_input( $site_id );
		if ( empty( $site_id ) ) {
			return new WP_Error( 'invalid_site_id', __( 'Invalid site identifier.', 'nexifymy-security' ) );
		}

		$credit_value = self::get_contribution_credit_value( $contribution_type );
		if ( $credit_value <= 0 ) {
			return new WP_Error( 'invalid_contribution_type', __( 'Unknown contribution type.', 'nexifymy-security' ) );
		}

		$multiplier = max( 1, absint( $value ) );
		$earned_now = $credit_value * $multiplier;

		$account                      = self::get_credit_account( $site_id );
		$account['credits_earned']    = intval( $account['credits_earned'] ) + $earned_now;
		$account['last_contribution'] = current_time( 'mysql' );
		$account['reputation_score']  = self::calculate_reputation_score( $site_id, $account['credits_earned'] );

		self::set_credit_account( $site_id, $account );
		self::increment_contribution_count( $site_id, $contribution_type, $multiplier );

		self::log(
			'p2p_credits_awarded',
			sprintf( 'Awarded %d credits (%s) to contributor %s', $earned_now, $contribution_type, substr( $site_id, 0, 12 ) ),
			'info',
			array(
				'site_id'           => $site_id,
				'contribution_type' => $contribution_type,
				'earned_now'        => $earned_now,
				'credits_earned'    => $account['credits_earned'],
				'reputation_score'  => $account['reputation_score'],
			)
		);

		$account['credits_awarded_now'] = $earned_now;
		$account['credit_balance']      = max( 0, intval( $account['credits_earned'] ) - intval( $account['credits_spent'] ) );
		$account['accuracy_percentage'] = self::get_accuracy_percentage( $site_id );
		$account['premium_free']        = self::is_premium_free( $account );
		$account['badges']              = self::get_badges_for_site( $site_id );

		return $account;
	}

	/**
	 * Spend credits for a specific benefit.
	 *
	 * @param int    $credits Explicit spend amount (optional).
	 * @param string $benefit_type Benefit slug.
	 * @param string $site_id Contributor site hash.
	 * @return array|WP_Error
	 */
	public static function spend_credits( $credits, $benefit_type, $site_id = '' ) {
		$site_id = self::normalize_site_id_input( $site_id );
		if ( empty( $site_id ) ) {
			return new WP_Error( 'invalid_site_id', __( 'Invalid site identifier.', 'nexifymy-security' ) );
		}

		$account       = self::get_credit_account( $site_id );
		$benefit_costs = self::get_benefit_cost_map();
		$benefit_type  = sanitize_key( $benefit_type );

		if ( ! isset( $benefit_costs[ $benefit_type ] ) ) {
			return new WP_Error( 'invalid_benefit_type', __( 'Unknown benefit type.', 'nexifymy-security' ) );
		}

		$cost = absint( $credits );
		if ( $cost <= 0 ) {
			$cost = $benefit_costs[ $benefit_type ];
		}

		$premium_free = self::is_premium_free( $account );
		if ( $premium_free ) {
			$cost = 0;
		}

		$balance = max( 0, intval( $account['credits_earned'] ) - intval( $account['credits_spent'] ) );
		if ( $balance < $cost ) {
			return new WP_Error( 'insufficient_credits', __( 'Insufficient credits for this benefit.', 'nexifymy-security' ) );
		}

		$account['credits_spent']    = intval( $account['credits_spent'] ) + $cost;
		$account['reputation_score'] = self::calculate_reputation_score( $site_id, $account['credits_earned'] );

		self::set_credit_account( $site_id, $account );
		self::record_benefit_redemption( $site_id, $benefit_type, $cost, $premium_free );

		self::log(
			'p2p_credits_spent',
			sprintf( 'Redeemed benefit %s for contributor %s', $benefit_type, substr( $site_id, 0, 12 ) ),
			'info',
			array(
				'site_id'      => $site_id,
				'benefit_type' => $benefit_type,
				'spent'        => $cost,
				'premium_free' => $premium_free,
			)
		);

		$account['spent_now']           = $cost;
		$account['credit_balance']      = max( 0, intval( $account['credits_earned'] ) - intval( $account['credits_spent'] ) );
		$account['accuracy_percentage'] = self::get_accuracy_percentage( $site_id );
		$account['premium_free']        = $premium_free;
		$account['benefit_type']        = $benefit_type;
		$account['badges']              = self::get_badges_for_site( $site_id );

		return $account;
	}

	/**
	 * Update contributor accuracy based on peer feedback.
	 *
	 * +10 when confirmed by peers, -20 when marked as false positive.
	 *
	 * @param string $site_id Contributor site hash.
	 * @param bool   $confirmed Whether feedback is a confirmation.
	 * @return int New accuracy percentage.
	 */
	public static function update_accuracy_by_feedback( $site_id, $confirmed = true ) {
		$site_id = self::normalize_site_id_input( $site_id );
		if ( empty( $site_id ) ) {
			return 100;
		}

		$accuracy  = self::get_accuracy_percentage( $site_id );
		$accuracy += $confirmed ? 10 : -20;
		$accuracy  = max( 0, min( 200, $accuracy ) );

		$accuracy_map             = self::get_accuracy_map();
		$accuracy_map[ $site_id ] = $accuracy;
		update_option( self::CREDITS_ACCURACY_OPTION, $accuracy_map, false );

		$account                     = self::get_credit_account( $site_id );
		$account['reputation_score'] = self::calculate_reputation_score( $site_id, $account['credits_earned'] );
		self::set_credit_account( $site_id, $account );

		return $accuracy;
	}

	/**
	 * Retrieve account data for a site hash.
	 *
	 * @param string $site_id Contributor site hash.
	 * @return array
	 */
	public static function get_credit_account( $site_id = '' ) {
		$site_id = self::normalize_site_id_input( $site_id );
		if ( empty( $site_id ) ) {
			return self::get_default_credit_account( self::get_anonymous_site_id() );
		}

		$cache = self::get_credit_cache();
		if ( ! empty( $cache[ $site_id ] ) && is_array( $cache[ $site_id ] ) ) {
			return self::normalise_credit_account_row( $site_id, $cache[ $site_id ] );
		}

		$db_account = self::get_credit_account_from_table( $site_id );
		if ( ! empty( $db_account ) ) {
			$cache[ $site_id ] = $db_account;
			update_option( self::CREDITS_CACHE_OPTION, $cache, false );
			return self::normalise_credit_account_row( $site_id, $db_account );
		}

		return self::get_default_credit_account( $site_id );
	}

	/**
	 * Get leaderboard of top contributors.
	 *
	 * @param int $limit Number of rows.
	 * @return array
	 */
	public static function get_credit_leaderboard( $limit = 10 ) {
		$limit = max( 1, min( 50, absint( $limit ) ) );
		$cache = self::get_credit_cache();
		$rows  = array();

		foreach ( $cache as $site_id => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$account = self::normalise_credit_account_row( $site_id, $row );
			$rows[]  = array(
				'site_id'             => $site_id,
				'anonymous_site_id'   => self::mask_site_id( $site_id ),
				'credits_earned'      => $account['credits_earned'],
				'credits_spent'       => $account['credits_spent'],
				'credit_balance'      => max( 0, $account['credits_earned'] - $account['credits_spent'] ),
				'accuracy_percentage' => self::get_accuracy_percentage( $site_id ),
				'reputation_score'    => $account['reputation_score'],
			);
		}

		usort(
			$rows,
			function ( $a, $b ) {
				if ( floatval( $a['reputation_score'] ) === floatval( $b['reputation_score'] ) ) {
					return intval( $b['credits_earned'] ) <=> intval( $a['credits_earned'] );
				}
				return floatval( $b['reputation_score'] ) <=> floatval( $a['reputation_score'] );
			}
		);

		$rows = array_slice( $rows, 0, $limit );
		foreach ( $rows as $index => $row ) {
			$rows[ $index ]['rank'] = $index + 1;
		}

		return $rows;
	}

	/**
	 * Return badges for a site hash.
	 *
	 * @param string $site_id Contributor site hash.
	 * @return array
	 */
	public static function get_badges_for_site( $site_id = '' ) {
		$site_id = self::normalize_site_id_input( $site_id );
		if ( empty( $site_id ) ) {
			return array();
		}

		$account       = self::get_credit_account( $site_id );
		$contributions = self::get_contribution_map();
		$site_counts   = $contributions[ $site_id ] ?? array();
		$badges        = array();

		if ( floatval( $account['reputation_score'] ) > 1000 ) {
			$badges[] = 'Top Defender';
		}

		$zero_day_count = intval( $site_counts['zero_day'] ?? 0 );
		if ( $zero_day_count > 0 ) {
			$badges[] = 'Zero-Day Hunter';
		}

		return $badges;
	}

	/**
	 * REST callback to award credits.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function rest_earn_credits( WP_REST_Request $request ) {
		$site_id = $request->get_param( 'site_id' );
		$type    = $request->get_param( 'contribution_type' );
		$value   = absint( $request->get_param( 'value' ) );

		$result = self::award_credits( $site_id, $type, $value > 0 ? $value : 1 );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return new WP_REST_Response(
			array(
				'status'  => 'ok',
				'message' => 'Credits awarded.',
				'data'    => $result,
			),
			200
		);
	}

	/**
	 * REST callback to retrieve current balance/reputation.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public static function rest_my_credits( WP_REST_Request $request ) {
		$site_id = $request->get_param( 'site_id' );
		$site_id = self::normalize_site_id_input( $site_id );
		if ( empty( $site_id ) ) {
			$site_id = self::get_anonymous_site_id();
		}

		$account                        = self::get_credit_account( $site_id );
		$account['site_id']             = $site_id;
		$account['anonymous_site_id']   = self::mask_site_id( $site_id );
		$account['credit_balance']      = max( 0, intval( $account['credits_earned'] ) - intval( $account['credits_spent'] ) );
		$account['accuracy_percentage'] = self::get_accuracy_percentage( $site_id );
		$account['premium_free']        = self::is_premium_free( $account );
		$account['badges']              = self::get_badges_for_site( $site_id );
		$account['leaderboard_rank']    = self::get_site_rank( $site_id );

		return new WP_REST_Response(
			array(
				'status' => 'ok',
				'data'   => $account,
			),
			200
		);
	}

	/**
	 * REST callback to redeem benefits.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function rest_redeem_credits( WP_REST_Request $request ) {
		$site_id     = $request->get_param( 'site_id' );
		$benefit     = $request->get_param( 'benefit_type' );
		$credit_cost = absint( $request->get_param( 'credits' ) );

		$result = self::spend_credits( $credit_cost, $benefit, $site_id );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return new WP_REST_Response(
			array(
				'status'  => 'ok',
				'message' => 'Benefit redeemed.',
				'data'    => $result,
			),
			200
		);
	}

	/**
	 * Get local-site credit summary for admin widgets.
	 *
	 * @return array
	 */
	public static function get_my_credit_summary() {
		$site_id = self::get_anonymous_site_id();
		$account = self::get_credit_account( $site_id );

		return array(
			'site_id'             => $site_id,
			'anonymous_site_id'   => self::mask_site_id( $site_id ),
			'credits_earned'      => intval( $account['credits_earned'] ),
			'credits_spent'       => intval( $account['credits_spent'] ),
			'credit_balance'      => max( 0, intval( $account['credits_earned'] ) - intval( $account['credits_spent'] ) ),
			'reputation_score'    => floatval( $account['reputation_score'] ),
			'accuracy_percentage' => self::get_accuracy_percentage( $site_id ),
			'premium_free'        => self::is_premium_free( $account ),
			'badges'              => self::get_badges_for_site( $site_id ),
			'leaderboard_rank'    => self::get_site_rank( $site_id ),
		);
	}

	/**
	 * Get site hash using GDPR-friendly HMAC hashing.
	 *
	 * @param string $site_reference Raw site reference (URL, label, hash).
	 * @return string
	 */
	public static function get_anonymous_site_id( $site_reference = '' ) {
		$reference = is_string( $site_reference ) ? trim( $site_reference ) : '';

		if ( empty( $reference ) ) {
			$reference = home_url();
		}

		if ( preg_match( '/^[a-f0-9]{64}$/i', $reference ) ) {
			return strtolower( $reference );
		}

		$reference = self::normalise_site_reference( $reference );
		$salt      = function_exists( 'wp_salt' ) ? wp_salt( 'auth' ) : self::get_node_key();
		if ( empty( $salt ) ) {
			$salt = self::get_node_key();
		}

		return hash_hmac( 'sha256', $reference, $salt );
	}

	/**
	 * Get credits table name.
	 *
	 * @return string
	 */
	private static function get_credits_table_name() {
		global $wpdb;
		return $wpdb->prefix . self::CREDITS_TABLE;
	}

	/**
	 * Normalize inbound site_id values.
	 *
	 * @param string $site_id Site hash or URL.
	 * @return string
	 */
	private static function normalize_site_id_input( $site_id ) {
		$site_id = is_string( $site_id ) ? trim( $site_id ) : '';

		if ( empty( $site_id ) ) {
			return self::get_anonymous_site_id();
		}

		if ( preg_match( '/^[a-f0-9]{64}$/i', $site_id ) ) {
			return strtolower( $site_id );
		}

		return self::get_anonymous_site_id( $site_id );
	}

	/**
	 * Ensure site references are normalized before hashing.
	 *
	 * @param string $reference Site URL or identifier.
	 * @return string
	 */
	private static function normalise_site_reference( $reference ) {
		$reference = strtolower( trim( (string) $reference ) );

		if ( filter_var( $reference, FILTER_VALIDATE_URL ) ) {
			$parsed = wp_parse_url( $reference );
			if ( is_array( $parsed ) ) {
				$host      = sanitize_text_field( $parsed['host'] ?? '' );
				$path      = sanitize_text_field( $parsed['path'] ?? '' );
				$reference = rtrim( $host . $path, '/' );
			}
		}

		return $reference ?: 'unknown-site';
	}

	/**
	 * Return credit value for each contribution type.
	 *
	 * @param string $contribution_type Contribution slug.
	 * @return int
	 */
	private static function get_contribution_credit_value( $contribution_type ) {
		$map = array(
			'blocked_ip'          => 1,
			'ip_block'            => 1,
			'malware_signature'   => 5,
			'zero_day'            => 25,
			'zero_day_threat'     => 25,
			'high_quality_report' => 10,
		);

		$type = sanitize_key( $contribution_type );
		return intval( $map[ $type ] ?? 0 );
	}

	/**
	 * Cost map for redeemable benefits.
	 *
	 * @return array
	 */
	private static function get_benefit_cost_map() {
		return array(
			'priority_alerts'    => 5,
			'signature_db'       => 10,
			'advanced_analytics' => 20,
			'manual_analysis'    => 50,
		);
	}

	/**
	 * Compute reputation from earned credits and accuracy.
	 *
	 * @param string $site_id Contributor site hash.
	 * @param int    $credits_earned Earned credits.
	 * @return float
	 */
	private static function calculate_reputation_score( $site_id, $credits_earned ) {
		$accuracy = self::get_accuracy_percentage( $site_id );
		return round( ( floatval( $credits_earned ) * floatval( $accuracy ) ) / 100, 2 );
	}

	/**
	 * Get accuracy map from options.
	 *
	 * @return array
	 */
	private static function get_accuracy_map() {
		$map = get_option( self::CREDITS_ACCURACY_OPTION, array() );
		return is_array( $map ) ? $map : array();
	}

	/**
	 * Get accuracy percentage for site.
	 *
	 * @param string $site_id Contributor site hash.
	 * @return int
	 */
	private static function get_accuracy_percentage( $site_id ) {
		$map      = self::get_accuracy_map();
		$accuracy = isset( $map[ $site_id ] ) ? intval( $map[ $site_id ] ) : 100;
		return max( 0, min( 200, $accuracy ) );
	}

	/**
	 * Record validation votes for threat outcomes.
	 *
	 * @param string $ip IP identifier.
	 * @param string $vote Vote type: block|allowlist.
	 * @return bool True when allowlist vote becomes majority.
	 */
	private static function record_validation_vote( $ip, $vote ) {
		$ip = sanitize_text_field( (string) $ip );
		if ( empty( $ip ) ) {
			return false;
		}

		$vote = sanitize_key( $vote );
		if ( ! in_array( $vote, array( 'block', 'allowlist' ), true ) ) {
			return false;
		}

		$key  = self::VALIDATION_PREFIX . md5( $ip );
		$data = get_transient( $key );

		if ( ! is_array( $data ) ) {
			$data = array(
				'block'     => 0,
				'allowlist' => 0,
			);
		}

		$data[ $vote ] = intval( $data[ $vote ] ) + 1;
		set_transient( $key, $data, DAY_IN_SECONDS );

		return intval( $data['allowlist'] ) > intval( $data['block'] );
	}

	/**
	 * Whether site qualifies for free premium benefits.
	 *
	 * @param array $account Credit account.
	 * @return bool
	 */
	private static function is_premium_free( $account ) {
		return floatval( $account['reputation_score'] ?? 0 ) > 1000;
	}

	/**
	 * Increment contribution counters per site.
	 *
	 * @param string $site_id Contributor site hash.
	 * @param string $type Contribution type.
	 * @param int    $amount Amount to increment.
	 * @return void
	 */
	private static function increment_contribution_count( $site_id, $type, $amount = 1 ) {
		$map  = self::get_contribution_map();
		$type = sanitize_key( $type );

		if ( empty( $map[ $site_id ] ) || ! is_array( $map[ $site_id ] ) ) {
			$map[ $site_id ] = array();
		}

		$map[ $site_id ][ $type ] = intval( $map[ $site_id ][ $type ] ?? 0 ) + max( 1, absint( $amount ) );
		update_option( self::CREDITS_CONTRIBUTION_OPTION, $map, false );
	}

	/**
	 * Get contribution counters map.
	 *
	 * @return array
	 */
	private static function get_contribution_map() {
		$map = get_option( self::CREDITS_CONTRIBUTION_OPTION, array() );
		return is_array( $map ) ? $map : array();
	}

	/**
	 * Persist benefit redemption.
	 *
	 * @param string $site_id Site hash.
	 * @param string $benefit_type Benefit.
	 * @param int    $cost Cost spent.
	 * @param bool   $premium_free Whether redeemed for free.
	 * @return void
	 */
	private static function record_benefit_redemption( $site_id, $benefit_type, $cost, $premium_free ) {
		$benefits = get_option( self::CREDITS_BENEFITS_OPTION, array() );
		if ( ! is_array( $benefits ) ) {
			$benefits = array();
		}

		if ( empty( $benefits[ $site_id ] ) || ! is_array( $benefits[ $site_id ] ) ) {
			$benefits[ $site_id ] = array();
		}

		$is_monthly = in_array( $benefit_type, array( 'priority_alerts', 'advanced_analytics' ), true );
		$expires_at = $is_monthly ? gmdate( 'Y-m-d H:i:s', time() + MONTH_IN_SECONDS ) : null;

		$benefits[ $site_id ][ $benefit_type ] = array(
			'redeemed_at'  => current_time( 'mysql' ),
			'expires_at'   => $expires_at,
			'cost'         => intval( $cost ),
			'premium_free' => (bool) $premium_free,
		);

		update_option( self::CREDITS_BENEFITS_OPTION, $benefits, false );
	}

	/**
	 * Retrieve credit cache map.
	 *
	 * @return array
	 */
	private static function get_credit_cache() {
		$cache = get_option( self::CREDITS_CACHE_OPTION, array() );
		return is_array( $cache ) ? $cache : array();
	}

	/**
	 * Save a normalized account into cache and DB.
	 *
	 * @param string $site_id Contributor site hash.
	 * @param array  $account Account row.
	 * @return void
	 */
	private static function set_credit_account( $site_id, $account ) {
		$site_id = self::normalize_site_id_input( $site_id );
		$account = self::normalise_credit_account_row( $site_id, $account );

		$cache             = self::get_credit_cache();
		$cache[ $site_id ] = $account;
		update_option( self::CREDITS_CACHE_OPTION, $cache, false );

		self::save_credit_account_to_table( $site_id, $account );
	}

	/**
	 * Normalize an account row.
	 *
	 * @param string $site_id Contributor site hash.
	 * @param array  $row Source row.
	 * @return array
	 */
	private static function normalise_credit_account_row( $site_id, $row ) {
		return array(
			'site_id'           => $site_id,
			'credits_earned'    => intval( $row['credits_earned'] ?? 0 ),
			'credits_spent'     => intval( $row['credits_spent'] ?? 0 ),
			'reputation_score'  => floatval( $row['reputation_score'] ?? 0 ),
			'last_contribution' => ! empty( $row['last_contribution'] ) ? sanitize_text_field( $row['last_contribution'] ) : null,
		);
	}

	/**
	 * Return default account row.
	 *
	 * @param string $site_id Contributor site hash.
	 * @return array
	 */
	private static function get_default_credit_account( $site_id ) {
		return array(
			'site_id'           => $site_id,
			'credits_earned'    => 0,
			'credits_spent'     => 0,
			'reputation_score'  => 0,
			'last_contribution' => null,
		);
	}

	/**
	 * Save account row to DB table.
	 *
	 * @param string $site_id Contributor site hash.
	 * @param array  $account Account row.
	 * @return void
	 */
	private static function save_credit_account_to_table( $site_id, $account ) {
		global $wpdb;

		if ( empty( $wpdb ) || ! method_exists( $wpdb, 'insert' ) ) {
			return;
		}

		self::maybe_create_credits_table();

		$table = self::get_credits_table_name();
		$data  = array(
			'site_id'           => $site_id,
			'credits_earned'    => intval( $account['credits_earned'] ?? 0 ),
			'credits_spent'     => intval( $account['credits_spent'] ?? 0 ),
			'reputation_score'  => floatval( $account['reputation_score'] ?? 0 ),
			'last_contribution' => ! empty( $account['last_contribution'] ) ? $account['last_contribution'] : current_time( 'mysql' ),
		);

		$exists = 0;
		if ( method_exists( $wpdb, 'get_var' ) && method_exists( $wpdb, 'prepare' ) ) {
			$exists = intval( $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE site_id = %s", $site_id ) ) );
		}

		if ( $exists > 0 && method_exists( $wpdb, 'update' ) ) {
			$wpdb->update(
				$table,
				$data,
				array( 'site_id' => $site_id ),
				array( '%s', '%d', '%d', '%f', '%s' ),
				array( '%s' )
			);
			return;
		}

		$wpdb->insert(
			$table,
			$data,
			array( '%s', '%d', '%d', '%f', '%s' )
		);
	}

	/**
	 * Load account row from DB table.
	 *
	 * @param string $site_id Contributor site hash.
	 * @return array
	 */
	private static function get_credit_account_from_table( $site_id ) {
		global $wpdb;

		if ( empty( $wpdb ) || ! method_exists( $wpdb, 'get_row' ) || ! method_exists( $wpdb, 'prepare' ) ) {
			return array();
		}

		$table = self::get_credits_table_name();
		$row   = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT site_id, credits_earned, credits_spent, reputation_score, last_contribution FROM {$table} WHERE site_id = %s LIMIT 1",
				$site_id
			),
			ARRAY_A
		);

		return is_array( $row ) ? $row : array();
	}

	/**
	 * Get rank of a site in the reputation leaderboard.
	 *
	 * @param string $site_id Contributor site hash.
	 * @return int|null
	 */
	private static function get_site_rank( $site_id ) {
		$leaderboard = self::get_credit_leaderboard( 1000 );
		foreach ( $leaderboard as $entry ) {
			if ( $entry['site_id'] === $site_id ) {
				return intval( $entry['rank'] );
			}
		}

		return null;
	}

	/**
	 * Render masked site hash for anonymous leaderboard display.
	 *
	 * @param string $site_id Contributor site hash.
	 * @return string
	 */
	private static function mask_site_id( $site_id ) {
		$site_id = strtolower( sanitize_text_field( (string) $site_id ) );
		if ( strlen( $site_id ) < 12 ) {
			return $site_id;
		}

		return substr( $site_id, 0, 6 ) . '...' . substr( $site_id, -4 );
	}

	/*
	================================================================
	 *  6. CRON SYNC (HOURLY)
	 * ============================================================= */

	/**
	 * Hourly cron job: ping each peer's heartbeat endpoint to verify
	 * connectivity and update status.
	 *
	 * Future enhancement: pull batched threat lists from peers here.
	 *
	 * @return void
	 */
	public static function cron_sync() {

		$peers    = self::get_peers();
		$node_key = self::get_node_key();
		$changed  = false;

		foreach ( $peers as $index => $peer ) {

			$endpoint = trailingslashit( $peer['url'] )
				. 'wp-json/' . self::REST_NAMESPACE . self::REST_ROUTE_HEARTBEAT;

			$response = wp_remote_get(
				$endpoint,
				array(
					'timeout'   => self::HTTP_TIMEOUT,
					'headers'   => array(
						'X-NexifyMy-Node-Key' => $node_key,
					),
					'sslverify' => true,
				)
			);

			$peers[ $index ]['last_sync'] = current_time( 'mysql' );

			if ( is_wp_error( $response ) ) {

				$peers[ $index ]['last_status'] = 'error';

				self::log(
					'p2p_sync_failed',
					sprintf( 'Heartbeat failed for peer %s: %s', $peer['url'], $response->get_error_message() ),
					'warning',
					array(
						'peer'  => $peer['url'],
						'error' => $response->get_error_message(),
					)
				);

			} else {

				$code                           = wp_remote_retrieve_response_code( $response );
				$peers[ $index ]['last_status'] = ( $code >= 200 && $code < 300 ) ? 'ok' : 'error';

			}

			$changed = true;
		}

		if ( $changed ) {
			update_option( self::PEERS_OPTION, $peers );
		}
	}

	/*
	================================================================
	 *  6. HELPER / UTILITY METHODS
	 * ============================================================= */

	/**
	 * Create an HMAC-SHA256 signature for a payload.
	 *
	 * @param  array  $payload Associative array of data to sign.
	 * @param  string $secret  Shared secret (API key).
	 * @return string          Hex-encoded signature.
	 */
	private static function sign_payload( array $payload, $secret ) {

		// Sort keys for deterministic serialisation.
		ksort( $payload );
		$data = wp_json_encode( $payload );

		return hash_hmac( 'sha256', $data, $secret );
	}

	/**
	 * Increment the daily counter of received threats (for dashboard stats).
	 *
	 * Uses a transient that expires at midnight UTC.
	 *
	 * @return void
	 */
	private static function increment_daily_counter() {

		$key   = 'nexifymy_p2p_daily_count_' . gmdate( 'Ymd' );
		$count = intval( get_transient( $key ) );

		// Expire at the end of the current UTC day.
		$seconds_left = strtotime( 'tomorrow midnight UTC' ) - time();
		$seconds_left = max( $seconds_left, 1 );

		set_transient( $key, $count + 1, $seconds_left );
	}

	/**
	 * Get the number of threats received in the last 24 hours.
	 *
	 * @return int
	 */
	public static function get_daily_threat_count() {

		$key = 'nexifymy_p2p_daily_count_' . gmdate( 'Ymd' );

		return intval( get_transient( $key ) );
	}

	/**
	 * Retrieve and cache module settings.
	 *
	 * Recognised keys:
	 *
	 *   p2p_enabled            bool  Master switch.
	 *   p2p_broadcast_enabled  bool  Send threats to peers.
	 *   p2p_trust_threshold    int   Minimum score to auto-block (0–100).
	 *
	 * @return array
	 */
	public static function get_settings() {

		if ( null !== self::$settings_cache ) {
			return self::$settings_cache;
		}

		$defaults = array(
			'p2p_enabled'           => false,  // Off by default — opt-in
			'p2p_broadcast_enabled' => true,
			'p2p_trust_threshold'   => self::DEFAULT_TRUST_THRESHOLD,
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
	 * Flush settings cache (for tests / after programmatic changes).
	 *
	 * @return void
	 */
	public static function flush_settings_cache() {
		self::$settings_cache = null;
	}

	/**
	 * Log wrapper — delegates to the SentinelWP logger or falls back
	 * to PHP error_log().
	 *
	 * @param  string $type    Machine-readable event type.
	 * @param  string $message Human-readable description.
	 * @param  string $level   Severity level.
	 * @param  array  $data    Contextual data.
	 * @return void
	 */
	private static function log( $type, $message, $level = 'info', $data = array() ) {

		if ( class_exists( 'NexifyMy_Security_Logger' ) && method_exists( 'NexifyMy_Security_Logger', 'log' ) ) {
			NexifyMy_Security_Logger::log( $type, $message, $level, $data );
			return;
		}

        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		error_log(
			sprintf(
				'[SentinelWP P2P] [%s] [%s] %s | %s',
				strtoupper( $level ),
				$type,
				$message,
				wp_json_encode( $data )
			)
		);
	}

	/**
	 * Block an IP — delegates to the Firewall class.
	 *
	 * @param  string $ip     IP address.
	 * @param  string $reason Block reason.
	 * @return bool
	 */
	private static function block_ip( $ip, $reason = '' ) {

		if ( class_exists( 'NexifyMy_Security_Firewall' ) && method_exists( 'NexifyMy_Security_Firewall', 'block_ip' ) ) {
			return (bool) NexifyMy_Security_Firewall::block_ip( $ip, $reason );
		}

        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		error_log(
			sprintf(
				'[SentinelWP P2P] BLOCK_IP (firewall unavailable): %s — %s',
				$ip,
				$reason
			)
		);
		return false;
	}

	/**
	 * Get the client's IP address.
	 *
	 * @return string
	 */
	private static function get_client_ip() {
		$remote_addr     = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		if ( $remote_addr && in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			$headers = array(
				'HTTP_CF_CONNECTING_IP',
				'HTTP_X_FORWARDED_FOR',
				'HTTP_X_REAL_IP',
				'HTTP_CLIENT_IP',
			);

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
	 * Get this server's own IP (to prevent self-blocking).
	 *
	 * @return string
	 */
	private static function get_server_ip() {

		if ( ! empty( $_SERVER['SERVER_ADDR'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) );
		}
		// Fallback: resolve the hostname.
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		$ip   = gethostbyname( $host );

		return ( $ip !== $host ) ? $ip : '127.0.0.1';
	}

	/**
	 * Reset internal state (for unit tests).
	 *
	 * @internal
	 * @return void
	 */
	public static function _reset() {
		self::$initialised    = false;
		self::$settings_cache = null;
	}
}
