<?php
/**
 * Sync all locale PO files with the POT template.
 *
 * - Preserves existing translations.
 * - Appends only missing entries from POT.
 *
 * Usage:
 *   php build/sync-po-with-pot.php
 */

if ( php_sapi_name() !== 'cli' ) {
	die( "CLI only.\n" );
}

$lang_dir = dirname( __DIR__ ) . '/languages';
$pot_file = $lang_dir . '/nexifymy-security.pot';
$po_files = glob( $lang_dir . '/nexifymy-security-*.po' );

if ( ! file_exists( $pot_file ) ) {
	die( "POT file not found: {$pot_file}\n" );
}
if ( empty( $po_files ) ) {
	die( "No PO files found in {$lang_dir}\n" );
}

$pot_entries = parse_catalog_entries( file_get_contents( $pot_file ) );
$pot_map     = array();
foreach ( $pot_entries as $entry ) {
	if ( '' === $entry['msgid'] ) {
		continue; // Header.
	}
	$key             = build_entry_key( $entry );
	$pot_map[ $key ] = $entry;
}

if ( empty( $pot_map ) ) {
	die( "No translatable entries found in POT.\n" );
}

$total_added = 0;

foreach ( $po_files as $po_file ) {
	$po_content = file_get_contents( $po_file );
	if ( false === $po_content ) {
		echo basename( $po_file ) . ": skipped (unreadable)\n";
		continue;
	}

	$po_entries = parse_catalog_entries( $po_content );
	$po_keys    = array();
	foreach ( $po_entries as $entry ) {
		if ( null === $entry['msgid'] ) {
			continue;
		}
		$po_keys[ build_entry_key( $entry ) ] = true;
	}

	$missing_blocks = array();
	foreach ( $pot_map as $key => $entry ) {
		if ( isset( $po_keys[ $key ] ) ) {
			continue;
		}

		$missing_blocks[] = render_po_entry_block( $entry );
	}

	$added = count( $missing_blocks );
	if ( 0 === $added ) {
		echo basename( $po_file ) . ": already up to date\n";
		continue;
	}

	$append = "\n";
	foreach ( $missing_blocks as $block ) {
		$append .= $block . "\n\n";
	}

	if ( false === file_put_contents( $po_file, rtrim( $po_content ) . $append ) ) {
		echo basename( $po_file ) . ": write failed\n";
		continue;
	}

	$total_added += $added;
	echo basename( $po_file ) . ": added {$added} entries\n";
}

echo "Done. Added {$total_added} missing entries across locales.\n";

/**
 * Parse catalog entries from POT/PO content.
 *
 * @param string $content Catalog content.
 * @return array<int, array<string, mixed>>
 */
function parse_catalog_entries( $content ) {
	$lines = preg_split( "/\r\n|\n|\r/", (string) $content );
	if ( ! is_array( $lines ) ) {
		return array();
	}

	$entries     = array();
	$current     = init_catalog_entry();
	$current_key = null;
	$current_idx = null;

	foreach ( $lines as $line ) {
		$trim = trim( $line );

		if ( '' === $trim ) {
			push_catalog_entry( $entries, $current );
			$current     = init_catalog_entry();
			$current_key = null;
			$current_idx = null;
			continue;
		}

		if ( '#' === substr( $trim, 0, 1 ) ) {
			continue;
		}

		if ( preg_match( '/^msgctxt\s+(".*")$/', $trim, $m ) ) {
			$current['msgctxt']   = decode_po_text( $m[1] );
			$current['has_entry'] = true;
			$current_key          = 'msgctxt';
			$current_idx          = null;
			continue;
		}

		if ( preg_match( '/^msgid_plural\s+(".*")$/', $trim, $m ) ) {
			$current['msgid_plural'] = decode_po_text( $m[1] );
			$current['has_entry']    = true;
			$current_key             = 'msgid_plural';
			$current_idx             = null;
			continue;
		}

		if ( preg_match( '/^msgid\s+(".*")$/', $trim, $m ) ) {
			$current['msgid']     = decode_po_text( $m[1] );
			$current['has_entry'] = true;
			$current_key          = 'msgid';
			$current_idx          = null;
			continue;
		}

		if ( preg_match( '/^msgstr\[(\d+)\]\s+(".*")$/', $trim, $m ) ) {
			$idx = (int) $m[1];
			if ( ! isset( $current['msgstr_plural'][ $idx ] ) ) {
				$current['msgstr_plural'][ $idx ] = '';
			}
			$current['msgstr_plural'][ $idx ] .= decode_po_text( $m[2] );
			$current['has_entry']              = true;
			$current_key                       = 'msgstr_plural';
			$current_idx                       = $idx;
			continue;
		}

		if ( preg_match( '/^msgstr\s+(".*")$/', $trim, $m ) ) {
			$current['msgstr']    = decode_po_text( $m[1] );
			$current['has_entry'] = true;
			$current_key          = 'msgstr';
			$current_idx          = null;
			continue;
		}

		if ( preg_match( '/^(".*")$/', $trim, $m ) ) {
			$part = decode_po_text( $m[1] );
			if ( 'msgctxt' === $current_key ) {
				$current['msgctxt'] .= $part;
			} elseif ( 'msgid' === $current_key ) {
				$current['msgid'] .= $part;
			} elseif ( 'msgid_plural' === $current_key ) {
				$current['msgid_plural'] .= $part;
			} elseif ( 'msgstr' === $current_key ) {
				$current['msgstr'] .= $part;
			} elseif ( 'msgstr_plural' === $current_key && null !== $current_idx ) {
				$current['msgstr_plural'][ $current_idx ] .= $part;
			}
		}
	}

	push_catalog_entry( $entries, $current );
	return $entries;
}

/**
 * Initialize one parsed catalog entry.
 *
 * @return array<string, mixed>
 */
function init_catalog_entry() {
	return array(
		'has_entry'     => false,
		'msgctxt'       => '',
		'msgid'         => null,
		'msgid_plural'  => null,
		'msgstr'        => '',
		'msgstr_plural' => array(),
	);
}

/**
 * Push parsed entry into entries array.
 *
 * @param array<int, array<string, mixed>> $entries Entries list.
 * @param array<string, mixed>             $entry   Parsed entry.
 * @return void
 */
function push_catalog_entry( &$entries, $entry ) {
	if ( empty( $entry['has_entry'] ) || null === $entry['msgid'] ) {
		return;
	}
	$entries[] = $entry;
}

/**
 * Build unique key for entry matching.
 *
 * @param array<string, mixed> $entry Entry.
 * @return string
 */
function build_entry_key( $entry ) {
	$ctxt   = (string) $entry['msgctxt'];
	$msgid  = (string) $entry['msgid'];
	$plural = null !== $entry['msgid_plural'] ? (string) $entry['msgid_plural'] : '';
	return $ctxt . "\004" . $msgid . "\000" . $plural;
}

/**
 * Render PO block for one entry with empty translations.
 *
 * @param array<string, mixed> $entry Entry.
 * @return string
 */
function render_po_entry_block( $entry ) {
	$lines = array();

	if ( '' !== (string) $entry['msgctxt'] ) {
		$lines[] = 'msgctxt "' . escape_po_text( (string) $entry['msgctxt'] ) . '"';
	}

	$lines[] = 'msgid "' . escape_po_text( (string) $entry['msgid'] ) . '"';

	if ( null !== $entry['msgid_plural'] ) {
		$lines[] = 'msgid_plural "' . escape_po_text( (string) $entry['msgid_plural'] ) . '"';

		$plural_indexes = array_keys( (array) $entry['msgstr_plural'] );
		if ( empty( $plural_indexes ) ) {
			$plural_indexes = array( 0, 1 );
		}

		sort( $plural_indexes );
		foreach ( $plural_indexes as $index ) {
			$lines[] = 'msgstr[' . (int) $index . '] ""';
		}
	} else {
		$lines[] = 'msgstr ""';
	}

	return implode( "\n", $lines );
}

/**
 * Decode quoted PO text.
 *
 * @param string $quoted Quoted token.
 * @return string
 */
function decode_po_text( $quoted ) {
	$quoted = trim( (string) $quoted );
	if ( strlen( $quoted ) >= 2 && '"' === $quoted[0] && '"' === substr( $quoted, -1 ) ) {
		$quoted = substr( $quoted, 1, -1 );
	}
	return stripcslashes( $quoted );
}

/**
 * Escape text for PO output.
 *
 * @param string $text Raw text.
 * @return string
 */
function escape_po_text( $text ) {
	return addcslashes( $text, "\\\"\n\r\t" );
}
