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

    /* ================================================================
     *  Constants
     * ============================================================= */

    /** REST API namespace. */
    const REST_NAMESPACE = 'nexifymy/v1';

    /** REST route path for receiving threat intelligence. */
    const REST_ROUTE_RECEIVE = '/p2p/receive';

    /** REST route path for peer handshake / heartbeat. */
    const REST_ROUTE_HEARTBEAT = '/p2p/heartbeat';

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

    /* ================================================================
     *  Properties
     * ============================================================= */

    /** @var bool Prevents double-initialisation. */
    private static $initialised = false;

    /** @var array|null Cached module settings. */
    private static $settings_cache = null;

    /* ================================================================
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

    /* ================================================================
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
            return new WP_Error( 'max_peers', sprintf(
                __( 'Maximum number of peers (%d) reached.', 'nexifymy-security' ),
                self::MAX_PEERS
            ) );
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
            'id'            => wp_generate_uuid4(),
            'url'           => $url,
            'api_key'       => $api_key,
            'label'         => sanitize_text_field( $label ),
            'added_at'      => current_time( 'mysql' ),
            'last_sync'     => null,
            'last_status'   => 'unknown',
            'threats_sent'  => 0,
            'threats_recv'  => 0,
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

    /* ================================================================
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

            $response = wp_remote_post( $endpoint, array(
                'timeout'   => self::HTTP_TIMEOUT,
                'headers'   => $headers,
                'body'      => wp_json_encode( $payload ),
                'sslverify' => true,
                'blocking'  => true,
            ) );

            if ( is_wp_error( $response ) ) {

                $results[ $peer['url'] ] = $response;

                self::log(
                    'p2p_broadcast_failed',
                    sprintf(
                        'Failed to broadcast threat %s to peer %s: %s',
                        $ip, $peer['url'], $response->get_error_message()
                    ),
                    'warning',
                    array( 'peer' => $peer['url'], 'ip' => $ip, 'error' => $response->get_error_message() )
                );

                // Update peer status.
                $peers[ $index ]['last_status'] = 'error';

            } else {

                $code = wp_remote_retrieve_response_code( $response );

                if ( $code >= 200 && $code < 300 ) {
                    $results[ $peer['url'] ] = 'ok';
                    $peers[ $index ]['threats_sent'] = intval( $peer['threats_sent'] ) + 1;
                    $peers[ $index ]['last_status']  = 'ok';
                } else {
                    $body = wp_remote_retrieve_body( $response );
                    $results[ $peer['url'] ] = new WP_Error(
                        'peer_http_error',
                        sprintf( 'HTTP %d: %s', $code, substr( $body, 0, 200 ) )
                    );
                    $peers[ $index ]['last_status'] = 'error';

                    self::log(
                        'p2p_broadcast_error',
                        sprintf( 'Peer %s returned HTTP %d for threat %s', $peer['url'], $code, $ip ),
                        'warning',
                        array( 'peer' => $peer['url'], 'ip' => $ip, 'http_code' => $code )
                    );
                }
            }
        }

        // Persist updated peer stats.
        update_option( self::PEERS_OPTION, $peers );

        return $results;
    }

    /* ================================================================
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
        register_rest_route( self::REST_NAMESPACE, self::REST_ROUTE_RECEIVE, array(
            'methods'             => WP_REST_Server::CREATABLE, // POST
            'callback'            => array( __CLASS__, 'rest_receive_threat' ),
            'permission_callback' => array( __CLASS__, 'rest_permission_check' ),
            'args'                => self::get_receive_endpoint_args(),
        ) );

        /*
         * GET /wp-json/nexifymy/v1/p2p/heartbeat
         *
         * Lightweight endpoint for cron-based health checks.
         */
        register_rest_route( self::REST_NAMESPACE, self::REST_ROUTE_HEARTBEAT, array(
            'methods'             => WP_REST_Server::READABLE, // GET
            'callback'            => array( __CLASS__, 'rest_heartbeat' ),
            'permission_callback' => array( __CLASS__, 'rest_permission_check' ),
        ) );
    }

    /**
     * Define the accepted arguments for the /receive endpoint.
     *
     * @return array
     */
    private static function get_receive_endpoint_args() {

        return array(
            'ip' => array(
                'required'          => true,
                'type'              => 'string',
                'description'       => 'The IP address to block.',
                'validate_callback' => function ( $value ) {
                    return (bool) filter_var( $value, FILTER_VALIDATE_IP );
                },
                'sanitize_callback' => 'sanitize_text_field',
            ),
            'reason' => array(
                'required'          => false,
                'type'              => 'string',
                'default'           => 'Reported by P2P peer',
                'sanitize_callback' => 'sanitize_text_field',
            ),
            'score' => array(
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
            'source' => array(
                'required'          => false,
                'type'              => 'string',
                'sanitize_callback' => 'esc_url_raw',
            ),
            'type' => array(
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
                    'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '',
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
                $my_node_key     = self::get_node_key();
                $expected_sig    = self::sign_payload( $payload, $my_node_key );

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
            return new WP_REST_Response( array(
                'status'  => 'duplicate',
                'message' => 'This IP was already reported recently.',
            ), 200 );
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

        $blocked = false;

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

                    self::log(
                        'p2p_preemptive_block',
                        sprintf(
                            'Preemptively blocked IP %s reported by peer %s (score: %d)',
                            $ip, $peer_url, $score
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
                            $ip, $peer_url, $score
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
                    $ip, $peer_url, $score, $threshold
                ),
                'info',
                $intel
            );
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

        return new WP_REST_Response( array(
            'status'  => 'accepted',
            'blocked' => $blocked,
            'message' => $blocked
                ? 'IP has been preemptively blocked.'
                : 'Threat logged but below trust threshold.',
        ), 200 );
    }

    /**
     * REST callback: heartbeat endpoint for peer health checks.
     *
     * @param  WP_REST_Request $request
     * @return WP_REST_Response
     */
    public static function rest_heartbeat( WP_REST_Request $request ) {

        return new WP_REST_Response( array(
            'status'    => 'ok',
            'plugin'    => 'SentinelWP',
            'module'    => 'p2p-intelligence',
            'version'   => '1.0.0',
            'timestamp' => gmdate( 'c' ),
        ), 200 );
    }

    /* ================================================================
     *  5. CRON SYNC (HOURLY)
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

            $response = wp_remote_get( $endpoint, array(
                'timeout'   => self::HTTP_TIMEOUT,
                'headers'   => array(
                    'X-NexifyMy-Node-Key' => $node_key,
                ),
                'sslverify' => true,
            ) );

            $peers[ $index ]['last_sync'] = current_time( 'mysql' );

            if ( is_wp_error( $response ) ) {

                $peers[ $index ]['last_status'] = 'error';

                self::log(
                    'p2p_sync_failed',
                    sprintf( 'Heartbeat failed for peer %s: %s', $peer['url'], $response->get_error_message() ),
                    'warning',
                    array( 'peer' => $peer['url'], 'error' => $response->get_error_message() )
                );

            } else {

                $code = wp_remote_retrieve_response_code( $response );
                $peers[ $index ]['last_status'] = ( $code >= 200 && $code < 300 ) ? 'ok' : 'error';

            }

            $changed = true;
        }

        if ( $changed ) {
            update_option( self::PEERS_OPTION, $peers );
        }
    }

    /* ================================================================
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
        error_log( sprintf(
            '[SentinelWP P2P] [%s] [%s] %s | %s',
            strtoupper( $level ),
            $type,
            $message,
            wp_json_encode( $data )
        ) );
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
        error_log( sprintf(
            '[SentinelWP P2P] BLOCK_IP (firewall unavailable): %s — %s',
            $ip,
            $reason
        ) );
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
            return $_SERVER['SERVER_ADDR'];
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
