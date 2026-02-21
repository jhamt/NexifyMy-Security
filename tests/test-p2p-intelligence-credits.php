<?php
/**
 * Tests for P2P intelligence credits/reputation system.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/modules/p2p-intelligence.php';

class Test_P2P_Intelligence_Credits extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		global $nexifymy_test_options, $wpdb;
		$nexifymy_test_options = array();
		$wpdb->insert_calls    = array();
		$wpdb->update_calls    = array();
		NexifyMy_Security_P2P::_reset();
	}

	public function test_award_credits_for_blocked_ip() {
		$site_id = str_repeat( 'a', 64 );
		$result  = NexifyMy_Security_P2P::award_credits( $site_id, 'blocked_ip', 1 );

		$this->assertIsArray( $result );
		$this->assertSame( 1, $result['credits_earned'] );
		$this->assertSame( 0, $result['credits_spent'] );
		$this->assertSame( 1, $result['credit_balance'] );
	}

	public function test_accuracy_feedback_updates_reputation() {
		$site_id = str_repeat( 'b', 64 );
		NexifyMy_Security_P2P::award_credits( $site_id, 'zero_day', 1 );

		$accuracy = NexifyMy_Security_P2P::update_accuracy_by_feedback( $site_id, true );
		$account  = NexifyMy_Security_P2P::get_credit_account( $site_id );

		$this->assertSame( 110, $accuracy );
		$this->assertSame( 25, $account['credits_earned'] );
		$this->assertSame( 27.5, $account['reputation_score'] );
	}

	public function test_spend_credits_uses_benefit_default_cost() {
		$site_id = str_repeat( 'c', 64 );
		NexifyMy_Security_P2P::award_credits( $site_id, 'blocked_ip', 20 );

		$result = NexifyMy_Security_P2P::spend_credits( 0, 'signature_db', $site_id );

		$this->assertIsArray( $result );
		$this->assertSame( 10, $result['spent_now'] );
		$this->assertSame( 10, $result['credit_balance'] );
	}

	public function test_high_reputation_gets_premium_features_free() {
		$site_id = str_repeat( 'd', 64 );
		NexifyMy_Security_P2P::award_credits( $site_id, 'high_quality_report', 200 );

		$result = NexifyMy_Security_P2P::spend_credits( 0, 'manual_analysis', $site_id );

		$this->assertIsArray( $result );
		$this->assertTrue( $result['premium_free'] );
		$this->assertSame( 0, $result['spent_now'] );
	}

	public function test_leaderboard_orders_by_reputation_and_masks_ids() {
		$site_a = str_repeat( 'e', 64 );
		$site_b = str_repeat( 'f', 64 );

		NexifyMy_Security_P2P::award_credits( $site_a, 'blocked_ip', 20 );
		NexifyMy_Security_P2P::award_credits( $site_b, 'zero_day', 1 );

		$leaderboard = NexifyMy_Security_P2P::get_credit_leaderboard( 2 );

		$this->assertCount( 2, $leaderboard );
		$this->assertSame( $site_b, $leaderboard[0]['site_id'] );
		$this->assertStringContainsString( '...', $leaderboard[0]['anonymous_site_id'] );
	}
}
