<?php
/**
 * Manages the security modules.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Modules {

	/**
	 * Initialize modules.
	 */
	public function init() {
		// Module initialization logic will go here.
		$this->load_active_modules();
	}

	/**
	 * Load active modules.
	 */
	private function load_active_modules() {
		// Load Firewall Module.
		require_once NEXIFYMY_SECURITY_PATH . 'modules/firewall.php';
		$firewall = new NexifyMy_Security_Firewall();
		$firewall->init();

		// Load Scanner Module.
		require_once NEXIFYMY_SECURITY_PATH . 'modules/scanner.php';
		$scanner = new NexifyMy_Security_Scanner();
		$scanner->init();

		// Load Cleanup Module.
		require_once NEXIFYMY_SECURITY_PATH . 'modules/cleanup.php';
		$cleanup = new NexifyMy_Security_Cleanup();
		$cleanup->init();

		// Load Logger (initialized via main file, but ensure table exists).
		require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-logger.php';
		$logger = new NexifyMy_Security_Logger();
		$logger->init();

		// Load Rate Limiter Module.
		require_once NEXIFYMY_SECURITY_PATH . 'modules/rate-limiter.php';
		$rate_limiter = new NexifyMy_Security_RateLimiter();
		$rate_limiter->init();

		// Load Background Scanner Module.
		require_once NEXIFYMY_SECURITY_PATH . 'modules/background-scanner.php';
		$bg_scanner = new NexifyMy_Security_Background_Scanner();
		$bg_scanner->init();
	}
}
