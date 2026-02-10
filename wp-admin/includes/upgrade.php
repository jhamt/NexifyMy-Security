<?php
/**
 * Mock WordPress upgrade file for tests.
 */

if ( ! function_exists( 'dbDelta' ) ) {
	function dbDelta( $queries ) {
		return array();
	}
}
