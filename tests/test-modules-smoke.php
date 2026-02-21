<?php
/**
 * Smoke tests for module class loading.
 *
 * This ensures each module file can be loaded and its primary class exists.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';

class Test_Modules_Smoke extends \PHPUnit\Framework\TestCase {

	public function test_all_module_classes_load() {
		$modules = array(
			'modules/firewall.php'                  => 'NexifyMy_Security_Firewall',
			'modules/rate-limiter.php'              => 'NexifyMy_Security_RateLimiter',
			'modules/scanner.php'                   => 'NexifyMy_Security_Scanner',
			'modules/quarantine.php'                => 'NexifyMy_Security_Quarantine',
			'modules/cleanup.php'                   => 'NexifyMy_Security_Cleanup',
			'modules/database-security.php'         => 'NexifyMy_Security_Database',
			'modules/live-traffic.php'              => 'NexifyMy_Security_Live_Traffic',
			'modules/geo-blocking.php'              => 'NexifyMy_Security_Geo_Blocking',
			'modules/hardening.php'                 => 'NexifyMy_Security_Hardening',
			'modules/password-security.php'         => 'NexifyMy_Security_Password',
			'modules/cdn-integration.php'           => 'NexifyMy_Security_CDN',
			'modules/core-repair.php'               => 'NexifyMy_Security_Core_Repair',
			'modules/signature-updater.php'         => 'NexifyMy_Security_Signature_Updater',
			'modules/performance-optimizer.php'     => 'NexifyMy_Security_Performance',
			'modules/self-protection.php'           => 'NexifyMy_Security_Self_Protection',
			'modules/two-factor-auth.php'           => 'NexifyMy_Security_Two_Factor',
			'modules/hide-login.php'                => 'NexifyMy_Security_Hide_Login',
			'modules/login-captcha.php'             => 'NexifyMy_Security_Login_Captcha',
			'modules/background-scanner.php'        => 'NexifyMy_Security_Background_Scanner',
			'modules/supply-chain-security.php'     => 'NexifyMy_Security_Supply_Chain',
			'modules/proactive-security.php'        => 'NexifyMy_Security_Proactive',
			'modules/predictive-threat-hunting.php' => 'NexifyMy_Security_Predictive_Threat_Hunting',
			'modules/ai-threat-detection.php'       => 'NexifyMy_Security_AI_Threat_Detection',
			'modules/passkey-auth.php'              => 'NexifyMy_Security_Passkey',
			'modules/compliance-reporting.php'      => 'NexifyMy_Security_Compliance',
			'modules/consent-management.php'        => 'NexifyMy_Security_Consent_Management',
			'modules/developer-api.php'             => 'NexifyMy_Security_Developer_API',
			'modules/integrations.php'              => 'NexifyMy_Security_Integrations',
			'modules/vulnerability-scanner.php'     => 'NexifyMy_Security_Vulnerability_Scanner',
		);

		foreach ( $modules as $file => $class ) {
			require_once dirname( __DIR__ ) . '/' . $file;
			$this->assertTrue( class_exists( $class ), "Expected class {$class} from {$file}" );
		}
	}
}
